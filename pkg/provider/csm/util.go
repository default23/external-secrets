/*
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

package csm

import api "github.com/external-secrets/external-secrets/pkg/provider/csm/api"

func filter[S ~[]E, E any](s S, fn func(E) bool) S {
	var p S
	for _, v := range s {
		if fn(v) {
			p = append(p, v)
		}
	}

	return p
}

func secretMatchLabels(tags map[string]string) func(s *api.Secret) bool {
	return func(s *api.Secret) bool {
		for k, v := range tags {
			if s.GetLabels()[k] != v {
				return false
			}
		}

		return true
	}
}
