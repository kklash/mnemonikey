package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kklash/mnemonikey"
)

func TestMain(m *testing.M) {
	cmd := exec.Command("go", "build")
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			err = fmt.Errorf("%w: %s", err, exitErr.Stderr)
		}
		fmt.Fprintf(os.Stderr, "failed to build binary: %s\n", err)
		os.Exit(1)
	}

	os.Exit(m.Run())
}

func readWordsFile(filePath string) ([]string, error) {
	wordsData, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(wordsData)), nil
}

func TestMnemonikeyCLI(t *testing.T) {
	tempDir := t.TempDir()
	wordFile := filepath.Join(tempDir, "words")

	t.Run("generate", func(t *testing.T) {
		cmd := exec.Command("./mnemonikey", "generate", "-out-word-file", wordFile)
		stdout, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}

		// The generate subcommand should output only the PGP key to stdout.
		if !bytes.HasPrefix(stdout, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) ||
			!bytes.HasSuffix(stdout, []byte("-----END PGP PRIVATE KEY BLOCK-----\n")) {
			t.Fatalf("expected generated PGP key to be written to stdout, got: %s", stdout)
			return
		}

		words, err := readWordsFile(wordFile)
		if err != nil {
			t.Fatal(err)
		}

		expectedWordCount := mnemonikey.MnemonicVersion(0).MnemonicSize()
		if len(words) != expectedWordCount {
			t.Fatalf("expected to find %d words, got %d", expectedWordCount, len(words))
		}
	})

	t.Run("recover from stdin", func(t *testing.T) {
		cmd := exec.Command("./mnemonikey", "recover")

		stdout := new(bytes.Buffer)
		cmd.Stdout = stdout

		stdin, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}

		words, err := readWordsFile(wordFile)
		if err != nil {
			t.Fatal(err)
		}
		for _, word := range words {
			stdin.Write([]byte(word + "\n"))
		}

		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}

		stdoutBytes, err := io.ReadAll(stdout)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.HasPrefix(stdoutBytes, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) ||
			!bytes.HasSuffix(stdoutBytes, []byte("-----END PGP PRIVATE KEY BLOCK-----\n")) {
			t.Fatalf("expected generated PGP key to be written to stdout, got: %s", stdoutBytes)
			return
		}
	})

	t.Run("recover from file", func(t *testing.T) {
		cmd := exec.Command("./mnemonikey", "recover", "-in-word-file", wordFile)

		stdoutBytes, err := cmd.Output()
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.HasPrefix(stdoutBytes, []byte("-----BEGIN PGP PRIVATE KEY BLOCK-----")) ||
			!bytes.HasSuffix(stdoutBytes, []byte("-----END PGP PRIVATE KEY BLOCK-----\n")) {
			t.Fatalf("expected generated PGP key to be written to stdout, got: %s", stdoutBytes)
			return
		}
	})
}
