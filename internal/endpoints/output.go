package endpoints

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"text/tabwriter"
)

// WriteJSON writes the inventory as indented JSON.
func WriteJSON(w io.Writer, inv *Inventory) error {
	raw, err := json.MarshalIndent(inv, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", raw)
	return err
}

// WriteCSV writes one row per route with a stable header.
func WriteCSV(w io.Writer, inv *Inventory) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()
	if err := cw.Write([]string{"service", "framework", "method", "path", "handler", "file", "line", "protection", "roles", "confidence"}); err != nil {
		return err
	}
	for _, r := range inv.Routes {
		row := []string{r.Service, r.Framework, r.Method, r.Path, r.Handler, r.File,
			strconv.Itoa(r.Line), string(r.Protection), strings.Join(r.Roles, ";"), r.Confidence}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	return cw.Error()
}

// WriteTable writes the human view: one line per route, no wrapping.
func WriteTable(w io.Writer, inv *Inventory) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "SERVICE\tMETHOD\tPATH\tPROTECTION\tHANDLER\tFILE:LINE"); err != nil {
		return err
	}
	for _, r := range inv.Routes {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s:%d\n",
			r.Service, r.Method, r.Path, r.Protection, r.Handler, r.File, r.Line); err != nil {
			return err
		}
	}
	return tw.Flush()
}

// Write renders inv in the requested format (json|csv|table).
func Write(w io.Writer, inv *Inventory, format string) error {
	switch format {
	case "json":
		return WriteJSON(w, inv)
	case "csv":
		return WriteCSV(w, inv)
	case "table":
		return WriteTable(w, inv)
	default:
		return fmt.Errorf("unknown format %q (want json|csv|table)", format)
	}
}
