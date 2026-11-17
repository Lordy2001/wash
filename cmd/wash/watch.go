package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"wash/internal/manager"
	"wash/internal/paths"
)

// `wash watch`: record sessions as a passive viewer, play recordings back,
// and publish them on the website.
func watch(args []string) error {
	sub := "list"
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	one := func(what string) (string, error) {
		if len(args) != 1 {
			return "", fmt.Errorf("usage: wash watch %s %s", sub, what)
		}
		return args[0], nil
	}
	switch sub {
	case "list", "ls":
		var rs []manager.RecordingInfo
		if err := manager.Call(manager.Request{Op: "watch.list"}, &rs); err != nil {
			return err
		}
		printRecordings(rs)
	case "start", "record":
		id, err := one("SESSION_ID")
		if err != nil {
			return err
		}
		var r manager.RecordingInfo
		if err := manager.Call(manager.Request{Op: "watch.start", ID: id}, &r); err != nil {
			return err
		}
		fmt.Printf("recording %s (session %s, %s) to %s\n", r.ID, r.Session, r.Name, r.Path)
		fmt.Printf("stop with `wash watch stop %s`\n", r.Session)
	case "stop":
		id, err := one("SESSION_ID")
		if err != nil {
			return err
		}
		var r manager.RecordingInfo
		if err := manager.Call(manager.Request{Op: "watch.stop", ID: id}, &r); err != nil {
			return err
		}
		fmt.Printf("stopped recording %s: %s, %s\n", r.ID, clock(r.Dur), humanBytes(r.Size))
		if r.Hosted != nil {
			fmt.Println("the hosted copy is being updated:", r.Hosted.URL)
		}
		fmt.Printf("play it with `wash watch play %s`\n", r.ID)
	case "play":
		return play(args)
	case "host", "publish":
		id, err := one("FILE_ID")
		if err != nil {
			return err
		}
		var r manager.RecordingInfo
		if err := manager.CallTimeout(manager.Request{Op: "watch.host", ID: id}, &r, 30*time.Minute); err != nil {
			return err
		}
		fmt.Println(r.Hosted.URL)
		if r.State == "recording" {
			fmt.Fprintln(os.Stderr, "still recording: this publishes what is recorded so far; it is updated when the recording stops")
		}
		fmt.Fprintln(os.Stderr, "anyone with this link can watch the recording. Remove it with `wash watch unhost "+r.ID+"`")
	case "unhost", "unpublish":
		id, err := one("FILE_ID")
		if err != nil {
			return err
		}
		if err := manager.Call(manager.Request{Op: "watch.unhost", ID: id}, nil); err != nil {
			return err
		}
		fmt.Println("removed from the website:", id)
	case "rm", "delete":
		if len(args) == 0 {
			return errors.New("usage: wash watch rm FILE_ID...")
		}
		var errs []error
		for _, id := range args {
			if err := manager.Call(manager.Request{Op: "watch.rm", ID: id}, nil); err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", id, err))
			} else {
				fmt.Println("deleted", id)
			}
		}
		return errors.Join(errs...)
	default:
		return fmt.Errorf("unknown watch command %q", sub)
	}
	return nil
}

func recStatus(r manager.RecordingInfo) string {
	var st string
	switch {
	case r.State == "recording" && r.Reason != "":
		st = "recording (reconnecting: " + r.Reason + ")"
	case r.State == "recording":
		st = "recording"
	case r.Reason != "" && r.Reason != "stopped":
		st = "stopped (" + r.Reason + ")"
	default:
		st = "stopped"
	}
	if r.Hosted != nil {
		switch {
		case r.State == "recording":
			st += ", hosted (snapshot)"
		case r.Hosted.Size < r.Size:
			st += ", hosted (updating)"
		default:
			st += ", hosted"
		}
	}
	return st
}

func printRecordings(rs []manager.RecordingInfo) {
	if len(rs) == 0 {
		fmt.Println("no recordings. Start one with `wash watch start SESSION_ID` (see `wash ls`).")
		return
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSESSION\tSTATUS\tSTARTED\tLENGTH\tSIZE\tURL")
	for _, r := range rs {
		url := "-"
		if r.Hosted != nil {
			url = r.Hosted.URL
		}
		fmt.Fprintf(tw, "%s\t%s (%s)\t%s\t%s\t%s\t%s\t%s\n", r.ID, r.Session, r.Name, recStatus(r),
			ago(r.Started), clock(r.Dur), humanBytes(r.Size), url)
	}
	tw.Flush()
}

func clock(sec float64) string {
	s := int(sec + 0.5)
	if s >= 3600 {
		return fmt.Sprintf("%d:%02d:%02d", s/3600, s/60%60, s%60)
	}
	return fmt.Sprintf("%02d:%02d", s/60, s%60)
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1fG", float64(n)/(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1fM", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1fK", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%dB", n)
}

// recordingFile finds a recording by (a prefix of) its id, or takes a path
// to any asciicast v2 file. It reads the recordings dir directly, so playing
// works without washd.
func recordingFile(arg string) (path, id string, err error) {
	if strings.ContainsAny(arg, "/.") {
		if _, err := os.Stat(arg); err == nil {
			return arg, filepath.Base(arg), nil
		}
	}
	ents, err := os.ReadDir(paths.RecordingsDir())
	if err != nil {
		return "", "", err
	}
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".cast")
		if !ok || !strings.HasPrefix(name, arg) || len(arg) < 3 && name != arg {
			continue
		}
		if path != "" {
			return "", "", fmt.Errorf("recording id %s is ambiguous", arg)
		}
		path, id = filepath.Join(paths.RecordingsDir(), e.Name()), name
	}
	if path == "" {
		return "", "", fmt.Errorf("no recording %s (`wash watch list`)", arg)
	}
	return path, id, nil
}
