// Package main is a deliberately minimal, benign runtime-analysis fixture.
//
// It exists ONLY to provide recognizable Go runtime structures (pclntab,
// moduledata, a handful of live goroutines, heap allocations, and a couple
// of deterministic marker strings) inside a controlled memory image for
// GoMemForensics development and testing. It is NOT a malware sample and
// contains no network communication, no command execution, and no
// persistence behavior of any kind. The Phase 6D persistence-marker
// constants below (markerFake*) are inert string literals only - they are
// never written to the registry/filesystem/service manager/cron/systemd,
// never executed, and use obviously fake, fixture-specific names that
// could never be mistaken for a real path or command.
//
// Usage (see scripts/fixtures/build_fixture.ps1 / build_fixture.sh):
//
//	go build -o gomemforensics_fixture.exe fixture.go
//	./gomemforensics_fixture.exe
//
// While running, the fixture allocates a small amount of heap memory,
// starts a few long-lived goroutines, and sleeps so a memory image can be
// captured against it. It exits on its own after a bounded duration so it
// never lingers indefinitely in a test environment.
package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Deterministic marker strings, used as ground truth for Go string
// recovery validation (Phase 3). Kept as package-level (static/
// .rodata-resident) string literals on purpose. Categories, per the
// approved Phase 3 fixture plan: short literal, long literal, repeated
// literal, Unicode/UTF-8 literal, and empty string. Heap-created and
// dynamically-assembled strings are produced at runtime below
// (newHeapMarker, markerShared).
const (
	markerStatic   = "GOMEMFORENSICS_FIXTURE_STATIC_MARKER_39f1"
	markerBanner   = "gomemforensics benign go runtime fixture"
	markerEmpty    = ""
	markerRepeated = "GOMEMFORENSICS_REPEAT_MARKER"
	markerUnicode  = "GOMEMFORENSICS_UNICODE_MARKER_héllo_wörld_日本語_🔍"
	markerLong     = "GOMEMFORENSICS_LONG_MARKER_" +
		"AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEEEEEEEEEFFFFFFFFFFGGGGGGGGGG" +
		"HHHHHHHHHHIIIIIIIIIIJJJJJJJJJJKKKKKKKKKKLLLLLLLLLLMMMMMMMMMMNNNNNNNNNN" +
		"_END_OF_LONG_MARKER"

	// Phase 6D persistence-artifact-classifier fixture markers - inert
	// string literals only, never written anywhere, never executed. Fake,
	// obviously fixture-specific names (never a real registry path,
	// service name, or filesystem location).
	markerFakeRegistryRun = `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\GoMemForensicsFixtureTestValue`
	markerFakeSchtasks    = "schtasks /create /tn GoMemForensicsFixtureTestTask /tr fake.exe"
	markerFakeSystemdUnit = "/etc/systemd/system/gomemforensics-fixture-test.service"
	markerFakeCronPath    = "/etc/cron.d/gomemforensics-fixture-test"
	markerFakeAutostart   = "/home/fixture/.config/autostart/gomemforensics-fixture-test.desktop"
)

// fixtureRecord is a small heap-allocated type, so the fixture always has
// at least one clearly identifiable heap object containing a string field.
type fixtureRecord struct {
	Label   string
	Created time.Time
}

func newHeapMarker(n int) []*fixtureRecord {
	records := make([]*fixtureRecord, 0, n)
	for i := 0; i < n; i++ {
		records = append(records, &fixtureRecord{
			// Deliberately built with fmt.Sprintf so this string is
			// heap-allocated at runtime rather than a static constant.
			Label:   fmt.Sprintf("GOMEMFORENSICS_FIXTURE_HEAP_MARKER_%02d", i),
			Created: time.Now(),
		})
	}
	return records
}

// --- Phase 4 function-recovery fixture catalog -----------------------------
//
// Every function below is `//go:noinline` so it survives compilation as its
// own distinct `_func`/ftab entry (an inlined call leaves no CALL
// instruction and no separate function-table record to recover), and each
// is deliberately trivial and benign - no network, no persistence, no
// command execution. Categories, per the approved Phase 4 fixture plan:
// integer argument, string argument, multiple arguments, pointer argument,
// zero argument, constant argument, global/static address argument, nested
// function calls, a standard-library call, and an application-to-
// application call.

// globalStaticTarget is deliberately package-level (static/.rodata- or
// .data-resident) so a call passing its address exercises the "global/
// static address argument" fixture category distinctly from a
// stack/heap-local pointer.
var globalStaticTarget = "GOMEMFORENSICS_GLOBAL_STATIC_TARGET"

//go:noinline
func fixtureArgInt(n int) int {
	return n + 1
}

//go:noinline
func fixtureArgString(s string) int {
	return len(s)
}

//go:noinline
func fixtureArgMulti(a int, b string, c bool) string {
	if c {
		return fmt.Sprintf("%d:%s", a, b)
	}
	return b
}

//go:noinline
func fixtureArgPointer(p *fixtureRecord) string {
	if p == nil {
		return ""
	}
	return p.Label
}

//go:noinline
func fixtureArgZero() string {
	return markerBanner
}

//go:noinline
func fixtureArgConstant(flag int) bool {
	return flag != 0
}

//go:noinline
func fixtureArgGlobalAddress(p *string) int {
	return len(*p)
}

//go:noinline
func fixtureInnermost(n int) int {
	return n * 2
}

//go:noinline
func fixtureInner(n int) int {
	return fixtureInnermost(n) + 1
}

//go:noinline
func fixtureOuter(n int) int {
	// Nested function calls: outer -> inner -> innermost.
	return fixtureInner(n)
}

//go:noinline
func fixtureStdlibCall(s string) string {
	// Standard-library call fixture category.
	return strings.ToUpper(s)
}

//go:noinline
func fixtureHelperA(label string) string {
	// Application-to-application call fixture category: one of our own
	// package functions calling another.
	return fixtureHelperB(label)
}

//go:noinline
func fixtureHelperB(label string) string {
	return "helper:" + label
}

// runFixtureFunctionCatalog exercises every category above so each
// function - and each of its call sites - is reachable, not dead-code
// eliminated, and deterministic across runs.
func runFixtureFunctionCatalog() {
	record := &fixtureRecord{Label: "fixture-record", Created: time.Now()}

	fmt.Println("fixtureArgInt:", fixtureArgInt(41))
	fmt.Println("fixtureArgString:", fixtureArgString(markerStatic))
	fmt.Println("fixtureArgMulti:", fixtureArgMulti(7, "seven", true))
	fmt.Println("fixtureArgPointer:", fixtureArgPointer(record))
	fmt.Println("fixtureArgZero:", fixtureArgZero())
	fmt.Println("fixtureArgConstant:", fixtureArgConstant(1))
	fmt.Println("fixtureArgGlobalAddress:", fixtureArgGlobalAddress(&globalStaticTarget))
	fmt.Println("fixtureOuter (nested calls):", fixtureOuter(5))
	fmt.Println("fixtureStdlibCall:", fixtureStdlibCall("gomemforensics"))
	fmt.Println("fixtureHelperA (app-to-app call):", fixtureHelperA("fixture"))
}

// worker is a trivial, long-lived goroutine body: no I/O, no network, no
// command execution - it just loops on a timer until told to stop.
func worker(id int, stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			// Intentionally empty tick - just keeps the goroutine
			// alive and schedulable for goroutine-analysis fixtures
			// in a later phase.
		}
	}
}

// --- Phase 5 goroutine-recovery fixture catalog ----------------------------
//
// Deterministic, benign goroutine behaviors distinct from `worker` above -
// no network, no persistence, no command execution - covering the
// approved Phase 5 fixture plan's categories: a channel-blocked
// goroutine (plain send/receive, not select/ticker), a CPU-bound
// goroutine (bounded, no I/O), and nested function calls executed from
// within a goroutine (not just from main, unlike runFixtureFunctionCatalog).

//go:noinline
func fixtureGoroutineCPUWork(iterations int) int {
	// Deterministic, bounded CPU work - no I/O, no allocation-heavy
	// pattern, just arithmetic - so a captured stack sample has a
	// reasonable chance of landing inside this function's own frame.
	total := 0
	for i := 0; i < iterations; i++ {
		total += i * i
	}
	return total
}

// channelBlockedWorker deliberately blocks on a plain (non-select,
// non-buffered) channel receive until signaled - a distinct "goroutine
// blocked on channel" wait state from worker's ticker/select pattern.
func channelBlockedWorker(signal <-chan struct{}, done chan<- struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	<-signal // blocks here until the main goroutine sends
	fixtureInner(fixtureGoroutineCPUWork(1000)) // nested call, per the approved plan
	done <- struct{}{}
}

// cpuBoundWorker repeatedly performs bounded CPU work with a short
// deterministic pause between rounds, until told to stop - a distinct
// "actively executing" state from the channel-blocked/ticker-waiting
// goroutines above.
func cpuBoundWorker(stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-stop:
			return
		default:
			fixtureGoroutineCPUWork(5000)
			time.Sleep(50 * time.Millisecond)
		}
	}
}

func main() {
	fmt.Println(markerBanner)
	fmt.Println(markerStatic)
	fmt.Println(markerRepeated, markerRepeated, markerRepeated)
	fmt.Println(markerUnicode)
	fmt.Println(markerLong)
	fmt.Printf("empty marker length: %d\n", len(markerEmpty))
	// Phase 6D fixture markers: printed only to guarantee the compiler
	// keeps these inert constants in .rodata - never written to the
	// registry/filesystem/service manager/cron/systemd, never executed.
	fmt.Println(markerFakeRegistryRun)
	fmt.Println(markerFakeSchtasks)
	fmt.Println(markerFakeSystemdUnit)
	fmt.Println(markerFakeCronPath)
	fmt.Println(markerFakeAutostart)

	// A single dynamically-assembled backing array referenced by two
	// distinct variables (and thus, at runtime, potentially two distinct
	// Go string headers sharing one data_address) - the "string shared
	// between variables" fixture category.
	markerSharedOriginal := fmt.Sprintf("GOMEMFORENSICS_SHARED_MARKER_%s", "one-backing-array")
	markerSharedAlias := markerSharedOriginal
	fmt.Println(markerSharedOriginal, markerSharedAlias)

	records := newHeapMarker(8)
	fmt.Printf("allocated %d heap records\n", len(records))

	runFixtureFunctionCatalog()

	const goroutineCount = 4
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < goroutineCount; i++ {
		wg.Add(1)
		go worker(i, stop, &wg)
	}
	fmt.Printf("started %d worker goroutines\n", goroutineCount)

	// Phase 5 goroutine-recovery fixture catalog: a channel-blocked
	// goroutine, and a CPU-bound goroutine - both distinct wait/run
	// states from the ticker/select-based worker goroutines above.
	channelSignal := make(chan struct{})
	channelDone := make(chan struct{}, 1)
	wg.Add(1)
	go channelBlockedWorker(channelSignal, channelDone, &wg)

	wg.Add(1)
	go cpuBoundWorker(stop, &wg)

	// Stay alive long enough for a memory acquisition tool to capture
	// this process, then shut down cleanly on its own.
	runDuration := 5 * time.Minute
	if v := os.Getenv("GOMEMFORENSICS_FIXTURE_DURATION_SECONDS"); v != "" {
		var seconds int
		if _, err := fmt.Sscanf(v, "%d", &seconds); err == nil && seconds > 0 {
			runDuration = time.Duration(seconds) * time.Second
		}
	}
	time.Sleep(runDuration)

	close(channelSignal)
	<-channelDone
	close(stop)
	wg.Wait()
	fmt.Println("gomemforensics fixture exiting")
}
