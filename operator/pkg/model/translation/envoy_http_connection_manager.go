// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"fmt"

	envoy_config_core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	grpcStatsv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_stats/v3"
	grpcWebv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/grpc_web/v3"
	httpRouterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_type_matcher_v3 "github.com/envoyproxy/go-control-plane/envoy/type/matcher/v3"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/envoy"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

const (
	// ExtAuthzFilterNamePrefix is the prefix for ext_authz filter instance names.
	// Full name: "<prefix>/<clusterName>". Used as the TypedPerFilterConfig key on routes.
	ExtAuthzFilterNamePrefix = "envoy.filters.http.ext_authz"
)

// ExtAuthzFilterName returns the HCM filter instance name for a given ext_authz cluster.
func ExtAuthzFilterName(clusterName string) string {
	return fmt.Sprintf("%s/%s", ExtAuthzFilterNamePrefix, clusterName)
}

type HttpConnectionManagerMutator func(*httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager

func WithInternalAddressConfig(enableIpv4, enableIpv6 bool) HttpConnectionManagerMutator {
	return func(hcm *httpConnectionManagerv3.HttpConnectionManager) *httpConnectionManagerv3.HttpConnectionManager {
		hcm.InternalAddressConfig = &httpConnectionManagerv3.HttpConnectionManager_InternalAddressConfig{
			UnixSockets: false,
			CidrRanges:  envoy.GetInternalListenerCIDRs(enableIpv4, enableIpv6),
		}
		return hcm
	}
}

// httpConnectionManagerMutators returns a list of mutator functions for customizing the HTTP connection manager.
func (i *cecTranslator) httpConnectionManagerMutators() []HttpConnectionManagerMutator {
	return []HttpConnectionManagerMutator{
		WithInternalAddressConfig(i.Config.IPConfig.IPv4Enabled, i.Config.IPConfig.IPv6Enabled),
	}
}

// desiredHTTPConnectionManager returns a new HTTP connection manager filter with the given name and route.
// authFilters is a deduplicated list of external auth backends; one named ext_authz filter is added per entry,
// positioned before the terminal router filter so that per-route TypedPerFilterConfig can enable/disable each.
func (i *cecTranslator) desiredHTTPConnectionManager(name, routeName string, authFilters []*model.HTTPExternalAuthFilter) (ciliumv2.XDSResource, error) {
	httpFilters := []*httpConnectionManagerv3.HttpFilter{
		{
			Name: "envoy.filters.http.grpc_web",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&grpcWebv3.GrpcWeb{}),
			},
		},
		{
			Name: "envoy.filters.http.grpc_stats",
			ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
				TypedConfig: toAny(&grpcStatsv3.FilterConfig{
					EmitFilterState:     true,
					EnableUpstreamStats: true,
				}),
			},
		},
	}

	for _, af := range authFilters {
		f, err := buildExtAuthzHTTPFilter(af)
		if err != nil {
			return ciliumv2.XDSResource{}, err
		}
		httpFilters = append(httpFilters, f)
	}

	httpFilters = append(httpFilters, &httpConnectionManagerv3.HttpFilter{
		Name: "envoy.filters.http.router",
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(&httpRouterv3.Router{}),
		},
	})

	connectionManager := &httpConnectionManagerv3.HttpConnectionManager{
		StatPrefix: name,
		RouteSpecifier: &httpConnectionManagerv3.HttpConnectionManager_Rds{
			Rds: &httpConnectionManagerv3.Rds{RouteConfigName: routeName},
		},
		UseRemoteAddress: &wrapperspb.BoolValue{Value: true},
		SkipXffAppend:    false,
		HttpFilters:      httpFilters,
		UpgradeConfigs: []*httpConnectionManagerv3.HttpConnectionManager_UpgradeConfig{
			{UpgradeType: "websocket"},
		},
		CommonHttpProtocolOptions: &envoy_config_core.HttpProtocolOptions{
			MaxStreamDuration: &durationpb.Duration{
				Seconds: 0,
			},
		},
	}

	// Apply mutation functions for customizing the connection manager.
	for _, fn := range i.httpConnectionManagerMutators() {
		connectionManager = fn(connectionManager)
	}

	return toXdsResource(connectionManager, envoy.HttpConnectionManagerTypeURL)
}

// buildExtAuthzHTTPFilter creates a named HCM HttpFilter for the given external auth config.
func buildExtAuthzHTTPFilter(af *model.HTTPExternalAuthFilter) (*httpConnectionManagerv3.HttpFilter, error) {
	clusterName := getClusterName(af.Backend.Namespace, af.Backend.Name, af.Backend.Port.GetPort())
	filterName := ExtAuthzFilterName(clusterName)

	var config *extauthzv3.ExtAuthz
	if af.Protocol == "GRPC" {
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_GrpcService{
				GrpcService: &envoy_config_core.GrpcService{
					TargetSpecifier: &envoy_config_core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &envoy_config_core.GrpcService_EnvoyGrpc{
							ClusterName: clusterName,
							// Authority overrides the :authority pseudo-header sent to the
							// auth server. Without this, Envoy uses the cluster name, which
							// after CEC namespace-qualification contains slashes
							// ("ns/cec/cluster") that are illegal in an HTTP/2 authority
							// (RFC 7540 §8.1.2.3) and cause strict gRPC clients to reset
							// the connection before the handler runs.
							Authority: fmt.Sprintf("%s:%s", af.Backend.Name, af.Backend.Port.GetPort()),
						},
					},
				},
			},
			FailureModeAllow: af.FailureModeAllow,
		}
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	} else {
		httpSvc := &extauthzv3.HttpService{
			ServerUri: &envoy_config_core.HttpUri{
				Uri: fmt.Sprintf("http://%s:%s", af.Backend.Name, af.Backend.Port.GetPort()),
				HttpUpstreamType: &envoy_config_core.HttpUri_Cluster{
					Cluster: clusterName,
				},
				Timeout: &durationpb.Duration{Seconds: 10},
			},
			PathPrefix: af.PathPrefix,
		}
		if len(af.AllowedResponseHeaders) > 0 {
			httpSvc.AuthorizationResponse = &extauthzv3.AuthorizationResponse{
				AllowedUpstreamHeaders: toListStringMatcher(af.AllowedResponseHeaders),
			}
		}
		config = &extauthzv3.ExtAuthz{
			Services: &extauthzv3.ExtAuthz_HttpService{
				HttpService: httpSvc,
			},
			FailureModeAllow: af.FailureModeAllow,
		}
		if len(af.AllowedRequestHeaders) > 0 {
			config.AllowedHeaders = toListStringMatcher(af.AllowedRequestHeaders)
		}
	}

	if af.ForwardBody != nil && af.ForwardBody.MaxSize > 0 {
		config.WithRequestBody = &extauthzv3.BufferSettings{
			MaxRequestBytes: af.ForwardBody.MaxSize,
		}
	}

	return &httpConnectionManagerv3.HttpFilter{
		Name: filterName,
		ConfigType: &httpConnectionManagerv3.HttpFilter_TypedConfig{
			TypedConfig: toAny(config),
		},
	}, nil
}

// toListStringMatcher converts a list of exact header names into an Envoy ListStringMatcher.
func toListStringMatcher(headers []string) *envoy_type_matcher_v3.ListStringMatcher {
	patterns := make([]*envoy_type_matcher_v3.StringMatcher, 0, len(headers))
	for _, h := range headers {
		patterns = append(patterns, &envoy_type_matcher_v3.StringMatcher{
			MatchPattern: &envoy_type_matcher_v3.StringMatcher_Exact{
				Exact: h,
			},
			IgnoreCase: true,
		})
	}
	return &envoy_type_matcher_v3.ListStringMatcher{Patterns: patterns}
}
