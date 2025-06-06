package exporter

import (
	"fmt"
	"path/filepath"
	"testing"
	"os"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"
)


func TestExporter(t *testing.T) {
	testClass := []struct {
		name        string
		varDefs     string
		expected    []prometheus.Metric
	}{
		{
			name:  "scalar",
			varDefs: "a",
		},
		{
			name:  "counter",
			varDefs: "a:counter",
		},
		{
			name: 	"map",
			varDefs: "a:map",
		},
		{
			name:    "countermap",
			varDefs: "a:countermap",
		},
		{
			name:    "hist",
			varDefs: "h:hist",
		},
		{
			name:    "histmap",
			varDefs: "h:histmap",
		},
		{
			name:    "multi",
			varDefs: "a,b:counter,c:map,d:countermap,e:hist,f:histmap",
		},
	}

	for _, tc := range testClass {
		t.Run(tc.name, func(t *testing.T){
			scriptPath := filepath.Join("testdata", fmt.Sprintf("%s.bt", tc.name))
			expected, err := os.Open(filepath.Join("testdata",fmt.Sprintf("%s.metrics", tc.name)))
			require.NoError(t, err)

			exported, err := NewExporter("bpftrace", scriptPath, tc.varDefs)
			require.NoError(t, err)

			err = testutil.CollectAndCompare(exported, expected)
			require.NoError(t, err)

			exported.Stop()
		})
	}
}