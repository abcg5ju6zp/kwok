/*
Copyright 2026 The Kubernetes Authors.

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

// Package certrotate implements certificate rotation for long lived clusters.
//
// A rotation always targets a single, identifiable certificate generation. The
// whole operation is journaled on disk so that repeating the request resumes
// the same generation instead of starting a new one. New trust material is
// generated and validated in an isolated location before the running cluster
// is touched, components are switched in dependency order (etcd, the API
// server, controllers and finally clients), and the previous generation stays
// available until the new chain has been verified so that every component
// switch can be rolled back.
package certrotate
