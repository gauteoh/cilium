// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package translation

import (
	"testing"

	extauthzv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_authz/v3"
	httpConnectionManagerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/cilium/cilium/operator/pkg/model"
)

func Test_desiredHTTPConnectionManager(t *testing.T) {
	i := &cecTranslator{}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", nil)
	require.NoError(t, err)

	httpConnectionManager := &httpConnectionManagerv3.HttpConnectionManager{}
	err = proto.Unmarshal(res.Value, httpConnectionManager)

	require.NoError(t, err)

	require.Equal(t, "dummy-name", httpConnectionManager.StatPrefix)
	require.Equal(t, &httpConnectionManagerv3.HttpConnectionManager_Rds{
		Rds: &httpConnectionManagerv3.Rds{RouteConfigName: "dummy-route-name"},
	}, httpConnectionManager.GetRouteSpecifier())

	require.Len(t, httpConnectionManager.GetHttpFilters(), 3)
	require.Equal(t, "envoy.filters.http.grpc_web", httpConnectionManager.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", httpConnectionManager.GetHttpFilters()[1].Name)
	require.Equal(t, "envoy.filters.http.router", httpConnectionManager.GetHttpFilters()[2].Name)

	require.Len(t, httpConnectionManager.GetUpgradeConfigs(), 1)
	require.Equal(t, "websocket", httpConnectionManager.GetUpgradeConfigs()[0].UpgradeType)
}

func Test_desiredHTTPConnectionManager_withExtAuthz(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{
			Backend:  model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol: "GRPC",
		},
		{
			Backend:    model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:   "HTTP",
			PathPrefix: "/auth",
		},
	}

	i := &cecTranslator{}
	res, err := i.desiredHTTPConnectionManager("dummy-name", "dummy-route-name", authFilters)
	require.NoError(t, err)

	hcm := &httpConnectionManagerv3.HttpConnectionManager{}
	require.NoError(t, proto.Unmarshal(res.Value, hcm))

	// grpc_web, grpc_stats, ext_authz/grpc, ext_authz/http, router
	require.Len(t, hcm.GetHttpFilters(), 5)
	require.Equal(t, "envoy.filters.http.grpc_web", hcm.GetHttpFilters()[0].Name)
	require.Equal(t, "envoy.filters.http.grpc_stats", hcm.GetHttpFilters()[1].Name)
	require.Equal(t, "envoy.filters.http.ext_authz/default:grpc-authz:9000", hcm.GetHttpFilters()[2].Name)
	require.Equal(t, "envoy.filters.http.ext_authz/default:http-authz:8080", hcm.GetHttpFilters()[3].Name)
	require.Equal(t, "envoy.filters.http.router", hcm.GetHttpFilters()[4].Name)

	// Verify GRPC filter points to the right cluster
	grpcFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[2].GetTypedConfig().Value, grpcFilter))
	require.NotNil(t, grpcFilter.GetGrpcService())
	require.Equal(t, "default:grpc-authz:9000", grpcFilter.GetGrpcService().GetEnvoyGrpc().GetClusterName())

	// Verify HTTP filter has path prefix
	httpFilter := &extauthzv3.ExtAuthz{}
	require.NoError(t, proto.Unmarshal(hcm.GetHttpFilters()[3].GetTypedConfig().Value, httpFilter))
	require.NotNil(t, httpFilter.GetHttpService())
	require.Equal(t, "/auth", httpFilter.GetHttpService().GetPathPrefix())
	require.Equal(t, "default:http-authz:8080", httpFilter.GetHttpService().GetServerUri().GetCluster())
}

func Test_buildExtAuthzHTTPFilter_forwardBody(t *testing.T) {
	t.Run("forward body set on GRPC filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "grpc-authz", Namespace: "default", Port: &model.BackendPort{Port: 9000}},
			Protocol:    "GRPC",
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 4096},
		}
		filter, err := buildExtAuthzHTTPFilter(af)
		require.NoError(t, err)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(4096), config.GetWithRequestBody().GetMaxRequestBytes())
	})

	t.Run("forward body set on HTTP filter", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    "HTTP",
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 8192},
		}
		filter, err := buildExtAuthzHTTPFilter(af)
		require.NoError(t, err)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.NotNil(t, config.GetWithRequestBody())
		require.Equal(t, uint32(8192), config.GetWithRequestBody().GetMaxRequestBytes())
	})

	t.Run("no forward body when nil", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol: "HTTP",
		}
		filter, err := buildExtAuthzHTTPFilter(af)
		require.NoError(t, err)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})

	t.Run("no forward body when max size is zero", func(t *testing.T) {
		af := &model.HTTPExternalAuthFilter{
			Backend:     model.Backend{Name: "http-authz", Namespace: "default", Port: &model.BackendPort{Port: 8080}},
			Protocol:    "HTTP",
			ForwardBody: &model.ForwardBodyConfig{MaxSize: 0},
		}
		filter, err := buildExtAuthzHTTPFilter(af)
		require.NoError(t, err)
		config := &extauthzv3.ExtAuthz{}
		require.NoError(t, proto.Unmarshal(filter.GetTypedConfig().Value, config))
		require.Nil(t, config.GetWithRequestBody())
	})
}

func Test_buildExtAuthzPerRouteConfig(t *testing.T) {
	authFilters := []*model.HTTPExternalAuthFilter{
		{Backend: model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}}, Protocol: "GRPC"},
		{Backend: model.Backend{Name: "svc-b", Namespace: "ns", Port: &model.BackendPort{Port: 8080}}, Protocol: "HTTP"},
	}

	t.Run("route without auth disables all filters", func(t *testing.T) {
		cfg := buildExtAuthzPerRouteConfig(nil, authFilters)
		require.Len(t, cfg, 2)
		for _, v := range cfg {
			perRoute := &extauthzv3.ExtAuthzPerRoute{}
			require.NoError(t, proto.Unmarshal(v.Value, perRoute))
			require.True(t, perRoute.GetDisabled())
		}
	})

	t.Run("route with auth enables its filter and disables others", func(t *testing.T) {
		routeAuth := &model.HTTPExternalAuthFilter{
			Backend:  model.Backend{Name: "svc-a", Namespace: "ns", Port: &model.BackendPort{Port: 9000}},
			Protocol: "GRPC",
		}
		cfg := buildExtAuthzPerRouteConfig(routeAuth, authFilters)
		// Only svc-b should be disabled; svc-a has no entry (enabled by default)
		require.Len(t, cfg, 1)
		_, hasSvcA := cfg["envoy.filters.http.ext_authz/ns:svc-a:9000"]
		require.False(t, hasSvcA, "active auth filter must not be explicitly disabled")
		disabledEntry, hasSvcB := cfg["envoy.filters.http.ext_authz/ns:svc-b:8080"]
		require.True(t, hasSvcB)
		perRoute := &extauthzv3.ExtAuthzPerRoute{}
		require.NoError(t, proto.Unmarshal(disabledEntry.Value, perRoute))
		require.True(t, perRoute.GetDisabled())
	})

	t.Run("no auth filters returns nil", func(t *testing.T) {
		require.Nil(t, buildExtAuthzPerRouteConfig(nil, nil))
	})
}
