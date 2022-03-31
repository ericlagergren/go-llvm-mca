package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"

	"golang.org/x/sync/errgroup"
	exec "golang.org/x/sys/execabs"
)

func main() {
	if err := main1(); err != nil {
		log.SetFlags(0)
		var ue *usageError
		if errors.As(err, &ue) {
			log.Printf("%s: %v", os.Args[0], err)
			fs.Usage()
		} else {
			log.Fatalf("%s: %v", os.Args[0], err)
		}
	}
}

func main1() error {
	args := os.Args[1:]
	if len(args) == 0 {
		return help()
	}
	cmd := args[0]
	args = args[1:]

	// $exe help fix
	// $exe help run
	if cmd == "help" {
		if len(args) == 0 {
			return help()
		}
		cmd = args[0]
		args = []string{"-help"}
	}

	switch cmd {
	case "-h", "-help", "--help":
		return help()
	case "fix":
		return fixCmd(args[0], args[1:])
	case "run":
		return runCmd(args)
	default:
		return useErrf("%s: unknown command (see '%s help')", os.Args[0], cmd)
	}
}

type usageError struct {
	error
}

func useErr(s string) error {
	return &usageError{error: errors.New(s)}
}

func useErrf(format string, args ...interface{}) error {
	return &usageError{error: fmt.Errorf(format, args...)}
}

var fs = flag.NewFlagSet(os.Args[0], flag.ExitOnError)

func help() error {
	return fmt.Errorf("Usage: %s [fix | run] [options...]", os.Args[0])
}

func runCmd(args []string) error {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s run -s REGEXP BINARY\n", os.Args[0])
		fs.PrintDefaults()
		os.Exit(1)
	}
	var symReg string
	fs.StringVar(&symReg, "s", "", "only dump symbols matching this regexp")

	ourArgs := args
	var mcaArgs []string
	for i, s := range args {
		if s == "--" {
			ourArgs, mcaArgs = args[:i], args[i+1:]
			break
		}
	}
	fs.Parse(ourArgs)

	if symReg == "" {
		return useErr("must set -s flag")
	}
	if fs.NArg() == 0 {
		return useErr("missing binary")
	}

	cmd := exec.Command("go",
		"tool", "objdump",
		"-gnu",
		"-s", symReg,
		fs.Arg(0),
	)
	cmd.Stderr = os.Stderr
	rc, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	cmd2 := exec.Command("llvm-mca", mcaArgs...)
	cmd2.Stdout = os.Stdout
	cmd2.Stderr = os.Stderr
	wc, err := cmd2.StdinPipe()
	if err != nil {
		return err
	}

	var grp errgroup.Group
	grp.Go(func() error {
		defer wc.Close()
		var cfg fixConfig
		return cfg.fix(wc, rc)
	})
	if err := cmd.Start(); err != nil {
		return err
	}
	if err := cmd2.Start(); err != nil {
		return err
	}
	grp.Go(cmd.Wait)
	grp.Go(cmd2.Wait)
	return grp.Wait()
}

func fixCmd(path string, args []string) error {
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s fix -s REGEXP BINARY\n", os.Args[0])
		fs.PrintDefaults()
		os.Exit(1)
	}
	var (
		outPath string
		cfg     fixConfig
	)
	fs.StringVar(&outPath, "out", "", "output file path (default: stdout)")
	fs.BoolVar(&cfg.file, "file", true, "include file name in output")
	fs.BoolVar(&cfg.instr, "instr", false, "include encoded instructions in output")
	fs.BoolVar(&cfg.offset, "offset", false, "include offset in output")
	fs.BoolVar(&cfg.goAsm, "goasm", true, "include Go assembly in output")
	fs.Parse(args)

	w := io.WriteCloser(nopCloser{Writer: os.Stdout})
	if outPath != "" {
		var err error
		w, err = os.Create(outPath)
		if err != nil {
			return err
		}
		defer w.Close()
	}

	r, err := os.Open(path)
	if err != nil {
		return err
	}
	defer r.Close()

	if err := cfg.fix(w, r); err != nil {
		return err
	}
	return w.Close()
}

type fixConfig struct {
	file   bool
	offset bool
	instr  bool
	goAsm  bool
}

func (c fixConfig) fix(w io.Writer, r io.Reader) error {
	tw := tabwriter.NewWriter(w, 18, 8, 1, '\t', tabwriter.StripEscape)

	s := bufio.NewScanner(r)
	for s.Scan() {
		t := s.Text()
		if strings.HasPrefix(t, "TEXT ") {
			t = strings.TrimPrefix(t, "TEXT ")
			fmt.Fprintf(tw, "%s\n", mangle(t))
			continue
		}
		l, err := split(t)
		if err != nil {
			return err
		}
		if l.gnuAsm == "ret" {
			fmt.Fprintf(tw, "\t// stopping at %s\n", l.gnuAsm)
			break
		}
		fmt.Fprintf(tw, "  %s", l.gnuAsm)
		if c.file || c.offset || c.instr || c.goAsm {
			slash := false
			printf := func(format string, args ...interface{}) {
				if !slash {
					format = "// " + format
					slash = true
				}
				fmt.Fprintf(tw, "\t"+format, args...)
			}
			if c.file {
				printf("%s:%d", l.file, l.line)
			}
			if c.offset {
				printf("%#x", l.offset)
			}
			if c.instr {
				printf("%x", l.instr)
			}
			if c.goAsm {
				printf("%s", l.goAsm)
			}
		}
		fmt.Fprint(tw, "\n")
	}
	if err := s.Err(); err != nil {
		return err
	}
	return tw.Flush()
}

// line is one line of output from "go tool objdump".
//
// It matches
//
//    blake2b_arm64.s:334	0xfbf40			f94007e0		MOVD 8(RSP), R0                      // ldr x0, [sp,#8]
//    blake2b_arm64.s:335	0xfbf44			f94013e1		MOVD 32(RSP), R1                     // ldr x1, [sp,#32]
//
type line struct {
	file   string
	line   int
	offset int
	instr  []byte
	goAsm  string
	gnuAsm string
}

func split(s string) (line, error) {
	orig := s
	s = strings.TrimSpace(s)

	i := strings.IndexByte(s, ':')
	if i < 0 {
		return line{}, syntaxErr("missing colon in file name", orig)
	}
	file, s := s[:i], s[i+1:]

	num, s, err := readInt(s)
	if err != nil {
		return line{}, err
	}

	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "0x") {
		return line{}, syntaxErr("missing 0x prefix for offset", orig)
	}
	s = strings.TrimPrefix(s, "0x")
	off, s, err := readHexInt(s)
	if err != nil {
		return line{}, err
	}

	s = strings.TrimSpace(s)
	instr, s, err := readHex(s)
	if err != nil {
		return line{}, err
	}

	s = strings.TrimSpace(s)
	i = strings.Index(s, "// ")
	if i < 0 {
		return line{}, syntaxErr("missing GNU assembly comments", orig)
	}
	goAsm := strings.TrimSpace(s[:i])
	gnuAsm := strings.TrimSpace(s[i+len("// "):])

	return line{
		file:   file,
		line:   num,
		offset: off,
		instr:  instr,
		goAsm:  goAsm,
		gnuAsm: gnuAsm,
	}, nil
}

func readInt(s string) (int, string, error) {
	i := 0
	for i < len(s) {
		c := s[i]
		if c < '0' || c > '9' {
			break
		}
		i++
	}
	x, err := strconv.Atoi(s[:i])
	if err != nil {
		return 0, "", err
	}
	return x, s[i:], nil
}

func readHexInt(s string) (int, string, error) {
	i := 0
	for i < len(s) && isHex(s[i]) {
		i++
	}
	x, err := strconv.ParseInt(s[:i], 16, bits.UintSize)
	if err != nil {
		return 0, "", err
	}
	return int(x), s[i:], nil
}

func readHex(s string) ([]byte, string, error) {
	i := 0
	for i < len(s) && isHex(s[i]) {
		i++
	}
	buf, err := hex.DecodeString(s[:i])
	if err != nil {
		return nil, "", err
	}
	return buf, s[i:], nil
}

func isHex(c byte) bool {
	switch {
	case '0' <= c && c <= '9':
		return true
	case 'a' <= c && c <= 'f':
		return true
	case 'A' <= c && c <= 'F':
		return true
	default:
		return false
	}
}

func syntaxErr(s, line string) error {
	return fmt.Errorf("syntax error: %s (%s)", s, line)
}

var repl = strings.NewReplacer(
	"(", "_",
	")", "_",
	"*", "_",
	"[", "_",
	"]", "_",
	"/", "_",
	" ", "_",
	".", "_",
)

func mangle(s string) string {
	return repl.Replace(s) + ":"
}

type nopCloser struct {
	io.Writer
}

var _ io.WriteCloser = nopCloser{}

func (nopCloser) Close() error {
	return nil
}
