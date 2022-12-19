// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package vex

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/openvex/go-vex/pkg/vex"
	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/osv"
)

func TestVex(t *testing.T) {
	// helper function takes in an OSV entry and returns a populated
	// govulncheck.Vuln with a valid call trace that will result in
	// returned vuln to return the value of argument "called" on IsCalled.
	vuln := func(e *osv.Entry, called bool) *govulncheck.Vuln {
		v := &govulncheck.Vuln{}
		v.OSV = e
		if called {
			p := &govulncheck.Package{Path: "golang.org/p1"}
			v.Modules = append(v.Modules, &govulncheck.Module{
				Path:     "golang.org/p1",
				Packages: []*govulncheck.Package{p},
			})

			cs := govulncheck.CallStack{Symbol: "Foo"}
			p.CallStacks = []govulncheck.CallStack{cs}
		}

		return v
	}

	for _, test := range []struct {
		desc   string
		vulns  []*govulncheck.Vuln
		source bool
		want   []vex.Statement
	}{{
		desc:   "empty vulns",
		vulns:  []*govulncheck.Vuln{},
		source: true,
		want:   []vex.Statement{},
	}, {
		desc: "one called vuln",
		vulns: []*govulncheck.Vuln{
			vuln(&osv.Entry{
				ID: "vuln-id-1",
			}, true),
		},
		source: true,
		want: []vex.Statement{
			{
				Vulnerability: "vuln-id-1",
				Status:        vex.StatusUnderInvestigation,
			},
		},
	}, {
		desc: "one uncalled vuln",
		vulns: []*govulncheck.Vuln{
			vuln(&osv.Entry{
				ID: "vuln-id-1",
			}, false),
		},
		source: true,
		want: []vex.Statement{
			{
				Vulnerability: "vuln-id-1",
				Status:        vex.StatusNotAffected,
				StatusNotes:   vulnerableCodeNotInExecutePathStatusNotes,
				Justification: vex.VulnerableCodeNotInExecutePath,
			},
		},
	}, {
		desc: "propagate references",
		vulns: []*govulncheck.Vuln{
			vuln(&osv.Entry{
				ID:         "vuln-id-1",
				References: []osv.Reference{{Type: "REPORT", URL: "https://go.dev/issue/56694"}},
			}, false),
		},
		source: true,
		want: []vex.Statement{
			{
				Vulnerability:   "vuln-id-1",
				VulnDescription: "REPORT:https://go.dev/issue/56694",
				Status:          vex.StatusNotAffected,
				StatusNotes:     vulnerableCodeNotInExecutePathStatusNotes,
				Justification:   vex.VulnerableCodeNotInExecutePath,
			},
		},
	}, {
		desc: "mixed called vulns",
		vulns: []*govulncheck.Vuln{
			vuln(&osv.Entry{
				ID: "vuln-id-1",
			}, false),
			vuln(&osv.Entry{
				ID: "vuln-id-2",
			}, true),
		},
		source: true,
		want: []vex.Statement{
			{
				Vulnerability: "vuln-id-1",
				Status:        vex.StatusNotAffected,
				StatusNotes:   vulnerableCodeNotInExecutePathStatusNotes,
				Justification: vex.VulnerableCodeNotInExecutePath,
			},
			{
				Vulnerability: "vuln-id-2",
				Status:        vex.StatusUnderInvestigation,
			},
		},
	},
	} {
		t.Run(test.desc, func(tt *testing.T) {
			got := vexStatements(test.vulns, test.source)
			if d := cmp.Diff(got, test.want, cmpopts.EquateEmpty(), cmpopts.SortSlices(vexStatementSort)); len(d) > 0 {
				tt.Errorf("mismatch in vex statements, (-expected, +got): %s", d)
			}
		})
	}
}

func vexStatementSort(a, b vex.Statement) bool {
	return a.Vulnerability < b.Vulnerability
}
