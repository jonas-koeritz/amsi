// go:build windows

// The amsi package provides a Go wrapper of the Microsoft Antimalware Scan Interface.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/
package amsi

import (
	"errors"
	"fmt"
	"runtime"
	"syscall"
	"unsafe"
)

// Context holds references to an initialized AMSI context
type Context struct {
	amsiDLL *syscall.LazyDLL
	handle  uintptr

	procNotifyOperation *syscall.LazyProc
	procScanBuffer      *syscall.LazyProc
	procScanString      *syscall.LazyProc
}

// Session holds references to a session within an AMSI context and provides the main scanning functions
type Session struct {
	context *Context
	handle  uintptr
}

// Result values are provider specific return values.
//
// The antimalware provider may return a result between 1 and 32767, inclusive, as an estimated risk level.
// Go-AMSI adds an additional value (-1) to indicate that a result could not be obtained through AMSI.
//
// Any result equal to or larger than 32768 is considered malware, and the content should be blocked.
// Use the IsMalware() function to determine if a result considers the data to be malware.
//
// See: https://docs.microsoft.com/de-de/windows/win32/api/amsi/ne-amsi-amsi_result
type Result int

const (
	// Could not determine the risk level through AMSI
	ResultUnknown Result = -1

	// Known good. No detection found, and the result is likely not going to change after a future definition update.
	ResultClean Result = 0

	// No detection found, but the result might change after a future definition update.
	ResultNotDetected Result = 1

	// Administrator policy blocked this content on this machine (beginning of range).
	ResultBlockedByAdminStart Result = 16384

	// Administrator policy blocked this content on this machine (end of range).
	ResultBlockedByAdminEnd Result = 20479

	// Detection found. The content is considered malware and should be blocked.
	ResultDetected Result = 32768
)

// No data has been provided as input. Go-AMSI considers empty data to be clean
var ErrEmptyInputData = errors.New("empty input data")

// The AMSI context has not been initialized or already unininitialized
var ErrContextNotInitialized = errors.New("context not initialized")

// The AMSI session has already been closed
var ErrSessionClosed = errors.New("session closed")

// AMSI is not available on the host system
var ErrAmsiUnavailable = errors.New("AMSI is not available")

// Initialize initializes the AMSI API. It will return ErrAmsiUnavailable if AMSI is unavailable on the System.
// The appName can be chosen arbitrarily to identify the calling application to the Antimalware Scanning Interface.
//
// See: https://docs.microsoft.com/de-de/windows/win32/api/amsi/nf-amsi-amsiinitialize
func Initialize(appName string) (c *Context, err error) {
	runtime.LockOSThread()

	c = &Context{}
	appNamePtr, err := syscall.UTF16PtrFromString(appName)
	if err != nil {
		return nil, fmt.Errorf("invalid application name: %w", err)
	}

	c.amsiDLL = syscall.NewLazyDLL("Amsi.dll")
	err = c.amsiDLL.Load()
	if err != nil {
		return nil, ErrAmsiUnavailable
	}

	procAmsiInitialize := c.amsiDLL.NewProc("AmsiInitialize")
	_, _, err = procAmsiInitialize.Call(uintptr(unsafe.Pointer(appNamePtr)), uintptr(unsafe.Pointer(&c.handle)))
	if err != syscall.Errno(0) {
		return nil, fmt.Errorf("failed to initialize AMSI: %w", err)
	}

	// Cache procs here to avoid lookups for repeated calls
	c.procNotifyOperation = c.amsiDLL.NewProc("AmsiNotifyOperation")
	c.procScanBuffer = c.amsiDLL.NewProc("AmsiScanBuffer")
	c.procScanString = c.amsiDLL.NewProc("AmsiScanString")

	return c, nil
}

// OpenSession opens a session within which multiple scan requests can be correlated.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiopensession
func (c *Context) OpenSession() (s *Session, err error) {
	if c.handle == 0 {
		return nil, ErrContextNotInitialized
	}

	procAmsiOpenSession := c.amsiDLL.NewProc("AmsiOpenSession")

	s = &Session{
		context: c,
	}

	_, _, err = procAmsiOpenSession.Call(c.handle, uintptr(unsafe.Pointer(&s.handle)))
	if err != syscall.Errno(0) {
		return nil, fmt.Errorf("failed to open AMSI session: %w", err)
	}

	return s, nil
}

// NotifyOperation sends to the antimalware provider a notification of an arbitrary operation.
// The notification doesn't imply the request of an antivirus scan.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsinotifyoperation
func (c *Context) NotifyOperation(buffer []byte, contentName string) (result Result, err error) {
	if len(buffer) == 0 {
		return ResultClean, ErrEmptyInputData
	}

	if c.handle == 0 {
		return ResultUnknown, ErrContextNotInitialized
	}

	contentNamePtr, err := syscall.UTF16PtrFromString(contentName)
	if err != nil {
		return ResultUnknown, fmt.Errorf("invalid content name: %w", err)
	}

	var amsiResult int32
	_, _, err = c.procNotifyOperation.Call(
		c.handle,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(uint32(len(buffer))),
		uintptr(unsafe.Pointer(contentNamePtr)),
		uintptr(unsafe.Pointer(&amsiResult)),
	)

	if err != syscall.Errno(0) {
		return ResultUnknown, fmt.Errorf("AmsiNotifyOperation failed: %w", err)
	}

	return Result(amsiResult), nil
}

// Uninitialize removes the instance of the AMSI API that was originally opened by Initialize.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiuninitialize
func (c *Context) Uninitialize() error {
	runtime.UnlockOSThread()

	if c.handle == 0 {
		return ErrContextNotInitialized
	}

	procAmsiUninitialize := c.amsiDLL.NewProc("AmsiUninitialize")

	_, _, err := procAmsiUninitialize.Call(c.handle)
	c.handle = 0

	// BUG(jonas-koeritz): The AmsiUninitialize call will always return "The handle is invalid"
	// on my machine when a session has been created before.
	// Functionality doesn't seem to be affected by this and it can be ignored.
	if err != syscall.Errno(0) {
		return fmt.Errorf("failed to uninitialize AMSI: %w", err)
	}

	return nil
}

// Close is a convenience function that wraps Uninitialize().
func (c *Context) Close() error {
	if c.handle != 0 {
		return c.Uninitialize()
	}
	return ErrContextNotInitialized
}

// ScanString scans a string for malware.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring
func (s *Session) ScanString(data string, contentName string) (result Result, err error) {
	return s.context.ScanString(data, contentName, s)
}

// ScanString scans a string for malware.
// The session parameter is optional, pass nil to scan without associating the scan with a Session.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanstring
func (c *Context) ScanString(data string, contentName string, session *Session) (result Result, err error) {
	if len(data) == 0 {
		return ResultClean, ErrEmptyInputData
	}

	if c.handle == 0 {
		return ResultUnknown, ErrContextNotInitialized
	}

	sessionHandle := uintptr(0)
	if session != nil {
		sessionHandle = session.handle
	}

	contentNamePtr, err := syscall.UTF16PtrFromString(contentName)
	if err != nil {
		return ResultUnknown, fmt.Errorf("invalid content name: %w", err)
	}

	var amsiResult int32

	dataPtr, err := syscall.UTF16PtrFromString(data)
	if err != nil {
		return ResultUnknown, fmt.Errorf("invalid input data: %w", err)
	}

	_, _, err = c.procScanString.Call(
		c.handle,
		uintptr(unsafe.Pointer(dataPtr)),
		uintptr(unsafe.Pointer(contentNamePtr)),
		sessionHandle,
		uintptr(unsafe.Pointer(&amsiResult)),
	)

	if err != syscall.Errno(0) {
		return ResultUnknown, fmt.Errorf("AmsiScanString failed: %w", err)
	}

	return Result(amsiResult), nil
}

// ScanBuffer Scans a buffer-full of content for malware.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer
func (s *Session) ScanBuffer(buffer []byte, contentName string) (result Result, err error) {
	return s.context.ScanBuffer(buffer, contentName, s)
}

// ScanBuffer Scans a buffer-full of content for malware.
// The session parameter is optional, pass nil to scan without associating the scan with a Session.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiscanbuffer
func (c *Context) ScanBuffer(buffer []byte, contentName string, session *Session) (result Result, err error) {
	if len(buffer) == 0 {
		return ResultClean, ErrEmptyInputData
	}

	if c.handle == 0 {
		return ResultUnknown, ErrContextNotInitialized
	}

	sessionHandle := uintptr(0)
	if session != nil {
		sessionHandle = session.handle
	}

	contentNamePtr, err := syscall.UTF16PtrFromString(contentName)
	if err != nil {
		return ResultUnknown, fmt.Errorf("invalid content name: %w", err)
	}

	var amsiResult int32

	_, _, err = c.procScanBuffer.Call(
		c.handle,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(uint32(len(buffer))),
		uintptr(unsafe.Pointer(contentNamePtr)),
		sessionHandle,
		uintptr(unsafe.Pointer(&amsiResult)),
	)

	if err != syscall.Errno(0) {
		return ResultUnknown, fmt.Errorf("AmsiScanBuffer failed: %w", err)
	}

	return Result(amsiResult), nil
}

// Close closes a session that was opened by OpenSession.
// Close will return an error if the underlying Context has been uninitialized or the session has already been closed.
//
// See: https://docs.microsoft.com/en-us/windows/win32/api/amsi/nf-amsi-amsiclosesession
func (s *Session) Close() error {
	if s.context.handle == 0 {
		return ErrContextNotInitialized
	}

	if s.handle == 0 {
		return ErrSessionClosed
	}

	procCloseSession := s.context.amsiDLL.NewProc("AmsiCloseSession")

	_, _, err := procCloseSession.Call(s.context.handle, s.handle)
	if err != syscall.Errno(0) {
		return fmt.Errorf("failed to close AMSI session: %w", err)
	}

	s.handle = 0

	return nil
}

// IsMalware checks if the given result considers the data to be malware.
func (r Result) IsMalware() bool {
	return r >= ResultDetected
}
