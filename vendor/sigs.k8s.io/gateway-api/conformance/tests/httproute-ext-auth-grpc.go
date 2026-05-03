/*
Copyright The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tests

import (
	"testing"

	"k8s.io/apimachinery/pkg/types"

	"sigs.k8s.io/gateway-api/conformance/utils/http"
	"sigs.k8s.io/gateway-api/conformance/utils/kubernetes"
	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/gateway-api/pkg/features"
)

func init() {
	ConformanceTests = append(ConformanceTests, HTTPRouteExtAuthGRPC)
}

var HTTPRouteExtAuthGRPC = suite.ConformanceTest{
	ShortName:   "HTTPRouteExtAuthGRPC",
	Description: "An HTTPRoute with an ExternalAuth filter using the gRPC protocol should allow authorized requests and deny unauthorized ones",
	Manifests:   []string{"tests/httproute-ext-auth-grpc.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteExtAuth,
		features.SupportHTTPRouteExtAuthGRPC,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "grpc-ext-auth", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				TestCaseName: "request with valid Bearer token should be allowed",
				Request: http.Request{
					Path: "/grpc-ext-auth",
					Headers: map[string]string{
						"Authorization": "Bearer token1",
					},
				},
				Namespace: ns,
				Response: http.Response{
					StatusCode: 200,
				},
			},
			{
				TestCaseName: "request without authorization should be denied",
				Request: http.Request{
					Path: "/grpc-ext-auth",
				},
				Response: http.Response{
					StatusCode: 403,
				},
			},
			{
				TestCaseName: "request with invalid Bearer token should be denied",
				Request: http.Request{
					Path: "/grpc-ext-auth",
					Headers: map[string]string{
						"Authorization": "Bearer invalid-token",
					},
				},
				Response: http.Response{
					StatusCode: 403,
				},
			},
		}
		for i := range testCases {
			tc := testCases[i]
			t.Run(tc.GetTestCaseName(i), func(t *testing.T) {
				t.Parallel()
				http.MakeRequestAndExpectEventuallyConsistentResponse(t, suite.RoundTripper, suite.TimeoutConfig, gwAddr, tc)
			})
		}
	},
}
