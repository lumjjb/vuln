// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package vex provides functionality to support creation of VEX documents in the govulncheck command
package vex

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/openvex/go-vex/pkg/vex"

	"golang.org/x/vuln/exp/govulncheck"
	"golang.org/x/vuln/osv"
)

const (
	vulnerableCodeNotInExecutePathStatusNotes = "govulncheck call graph analysis determined vulnerable function not executed"
)

// PrintVex prints out a VEX statement from govulncheck based on the results
func PrintVex(r *govulncheck.Result, source bool) error {
	vexDoc := toDefaultVex(r, source)

	b, err := json.MarshalIndent(vexDoc, "", "\t")
	if err != nil {
		return err
	}
	os.Stdout.Write(b)
	fmt.Println()
	return nil
}

// toDefaultVex returns the VEX document given the information available in
// from the govulncheck result, making no additional assumptions about affected
// vulnerabilities.
func toDefaultVex(r *govulncheck.Result, source bool) vex.VEX {
	vexDoc := vex.New()
	vexDoc.Author = "PLEASE FILL IN"
	vexDoc.ID = fmt.Sprintf("VEX-govulncheck-%d", uuid.New().ID())
	vexDoc.Version = "1.0"
	vexDoc.Tooling = "govulncheck"

	// Based on "category of publisher" roles defined by CSAF 2.0
	vexDoc.AuthorRole = "discoverer"
	vexDoc.Statements = vexStatements(r.Vulns, source)
	return vexDoc
}

// vexStatements returns the list of VEX statements based on the status of the vulnerabilities
// provided by govulncheck
func vexStatements(vulns []*govulncheck.Vuln, source bool) []vex.Statement {
	var (
		statements          []vex.Statement
		unaffected, unknown []*govulncheck.Vuln
	)
	if source {
		unaffected, unknown = getUnaffected(vulns)
	} else {
		unknown = vulns
	}

	for _, v := range unaffected {
		vstmt := vex.Statement{
			Vulnerability:   v.OSV.ID,
			Status:          vex.StatusNotAffected,
			Justification:   vex.VulnerableCodeNotInExecutePath,
			StatusNotes:     vulnerableCodeNotInExecutePathStatusNotes,
			VulnDescription: convertOsvVulnRef(v.OSV.References),
		}
		statements = append(statements, vstmt)
	}

	for _, v := range unknown {
		vstmt := vex.Statement{
			Vulnerability:   v.OSV.ID,
			Status:          vex.StatusUnderInvestigation,
			VulnDescription: convertOsvVulnRef(v.OSV.References),
		}
		statements = append(statements, vstmt)
	}

	return statements
}

func getUnaffected(vulns []*govulncheck.Vuln) (unaffected, leftover []*govulncheck.Vuln) {
	// unaffected are (imported) OSVs none of
	// which vulnerabilities are called.
	for _, v := range vulns {
		if v.IsCalled() {
			leftover = append(leftover, v)
		} else {
			// save arbitrary Vuln for informational message
			unaffected = append(unaffected, v)
		}
	}

	return unaffected, leftover
}

func convertOsvVulnRef(refs []osv.Reference) string {
	refString := ""
	for i, r := range refs {
		if i != 0 {
			refString += "\n"
		}
		refString += fmt.Sprintf("%s:%s", r.Type, r.URL)
	}
	return refString
}
