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
	ConformanceTests = append(ConformanceTests, HTTPRouteExtAuthHTTPForwardBody)
}

var HTTPRouteExtAuthHTTPForwardBody = suite.ConformanceTest{
	ShortName:   "HTTPRouteExtAuthHTTPForwardBody",
	Description: "An HTTPRoute with an ExternalAuth HTTP filter and forwardBody configured should forward the request body to the authorization server and allow or deny accordingly",
	Manifests:   []string{"tests/httproute-ext-auth-http.yaml"},
	Features: []features.FeatureName{
		features.SupportGateway,
		features.SupportHTTPRoute,
		features.SupportHTTPRouteExtAuth,
		features.SupportHTTPRouteExtAuthHTTP,
		features.SupportHTTPRouteExtAuthForwardBody,
	},
	Test: func(t *testing.T, suite *suite.ConformanceTestSuite) {
		ns := "gateway-conformance-infra"
		routeNN := types.NamespacedName{Name: "http-ext-auth-forward-body", Namespace: ns}
		gwNN := types.NamespacedName{Name: "same-namespace", Namespace: ns}
		gwAddr := kubernetes.GatewayAndHTTPRoutesMustBeAccepted(t, suite.Client, suite.TimeoutConfig, suite.ControllerName, kubernetes.NewGatewayRef(gwNN), routeNN)
		kubernetes.HTTPRouteMustHaveResolvedRefsConditionsTrue(t, suite.Client, suite.TimeoutConfig, routeNN, gwNN)

		testCases := []http.ExpectedResponse{
			{
				TestCaseName: "POST with body and valid Bearer token should be allowed and x-current-user forwarded to backend",
				Request: http.Request{
					Method: "POST",
					Path:   "/http-ext-auth-forward-body",
					Headers: map[string]string{
						"Authorization": "Bearer token1",
					},
					Body: "conformance test request body",
				},
				ExpectedRequest: &http.ExpectedRequest{
					Request: http.Request{
						Method: "POST",
						Path:   "/http-ext-auth-forward-body",
						Headers: map[string]string{
							"x-current-user": "user1",
						},
					},
				},
				Namespace: ns,
				Response: http.Response{
					StatusCode: 200,
				},
			},
			{
				TestCaseName: "POST with body and invalid Bearer token should be denied",
				Request: http.Request{
					Method: "POST",
					Path:   "/http-ext-auth-forward-body",
					Headers: map[string]string{
						"Authorization": "Bearer invalid-token",
					},
					Body: "conformance test request body",
				},
				Response: http.Response{
					StatusCode: 403,
				},
			},
			{
				TestCaseName: "POST with body and no authorization should be denied",
				Request: http.Request{
					Method: "POST",
					Path:   "/http-ext-auth-forward-body",
					Body:   "conformance test request body",
				},
				Response: http.Response{
					StatusCode: 403,
				},
			},
			{
				// maxSize on the route is 1024 bytes; send 1025 to exceed it.
				// Per spec, bodies over maxSize must be rejected with a 4xx error
				// (413 Request Entity Too Large or 403 Forbidden are both valid).
				TestCaseName: "POST with body exceeding forwardBody maxSize should be rejected",
				Request: http.Request{
					Method: "POST",
					Path:   "/http-ext-auth-forward-body",
					Headers: map[string]string{
						"Authorization": "Bearer token1",
					},
					Body: string(make([]byte, 1025)),
				},
				Response: http.Response{
					StatusCodes: []int{413, 403},
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
