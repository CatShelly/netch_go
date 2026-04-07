//go:build windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	goruntime "runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	wmNull             = 0x0000
	wmDestroy          = 0x0002
	wmClose            = 0x0010
	wmCommand          = 0x0111
	wmContextMenu      = 0x007B
	wmRButtonUp        = 0x0205
	wmLButtonUp        = 0x0202
	wmLButtonDblClk    = 0x0203
	wmTrayCallback     = 0x8001
	mfString           = 0x0000
	tpmRightButton     = 0x0002
	imageIcon          = 1
	lrLoadFromFile     = 0x0010
	lrDefaultSize      = 0x0040
	nifMessage         = 0x00000001
	nifIcon            = 0x00000002
	nifTip             = 0x00000004
	nimAdd             = 0x00000000
	nimDelete          = 0x00000002
	nimSetVersion      = 0x00000004
	notifyIconVersion4 = 4
	idiApplication     = 32512
	trayIconID         = 1
	trayMenuShow       = 1001
	trayMenuHide       = 1002
	trayMenuExit       = 1003
)

var (
	modUser32  = windows.NewLazySystemDLL("user32.dll")
	modShell32 = windows.NewLazySystemDLL("shell32.dll")
	modKernel  = windows.NewLazySystemDLL("kernel32.dll")

	procRegisterClassExW    = modUser32.NewProc("RegisterClassExW")
	procCreateWindowExW     = modUser32.NewProc("CreateWindowExW")
	procDefWindowProcW      = modUser32.NewProc("DefWindowProcW")
	procDestroyWindow       = modUser32.NewProc("DestroyWindow")
	procGetMessageW         = modUser32.NewProc("GetMessageW")
	procTranslateMessage    = modUser32.NewProc("TranslateMessage")
	procDispatchMessageW    = modUser32.NewProc("DispatchMessageW")
	procPostMessageW        = modUser32.NewProc("PostMessageW")
	procPostQuitMessage     = modUser32.NewProc("PostQuitMessage")
	procLoadIconW           = modUser32.NewProc("LoadIconW")
	procLoadImageW          = modUser32.NewProc("LoadImageW")
	procDestroyIcon         = modUser32.NewProc("DestroyIcon")
	procCreatePopupMenu     = modUser32.NewProc("CreatePopupMenu")
	procAppendMenuW         = modUser32.NewProc("AppendMenuW")
	procTrackPopupMenu      = modUser32.NewProc("TrackPopupMenu")
	procDestroyMenu         = modUser32.NewProc("DestroyMenu")
	procGetCursorPos        = modUser32.NewProc("GetCursorPos")
	procSetForegroundWindow = modUser32.NewProc("SetForegroundWindow")
	procGetModuleHandleW    = modKernel.NewProc("GetModuleHandleW")
	procShellNotifyIconW    = modShell32.NewProc("Shell_NotifyIconW")
	procExtractIconExW      = modShell32.NewProc("ExtractIconExW")

	trayWndProc = syscall.NewCallback(trayWindowProc)
	trayByHwnd  sync.Map
)

type windowsTrayController struct {
	app       *App
	className string

	mu      sync.Mutex
	hwnd    windows.Handle
	started bool
	ready   bool
	done    chan struct{}
	icon    windows.Handle
	iconOwn bool
}

type winPoint struct {
	X int32
	Y int32
}

type winMSG struct {
	HWnd     windows.Handle
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       winPoint
	LPrivate uint32
}

type winWNDCLASSEX struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     windows.Handle
	HIcon         windows.Handle
	HCursor       windows.Handle
	HbrBackground windows.Handle
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       windows.Handle
}

type notifyIconData struct {
	CbSize            uint32
	HWnd              windows.Handle
	UID               uint32
	UFlags            uint32
	UCallbackMessage  uint32
	HIcon             windows.Handle
	SzTip             [128]uint16
	DwState           uint32
	DwStateMask       uint32
	SzInfo            [256]uint16
	UTimeoutOrVersion uint32
	SzInfoTitle       [64]uint16
	DwInfoFlags       uint32
	GuidItem          windows.GUID
	HBalloonIcon      windows.Handle
}

func newTrayController(app *App) trayController {
	return &windowsTrayController{
		app:       app,
		className: fmt.Sprintf("NetchGoTrayWindow_%d", time.Now().UnixNano()),
	}
}

func (t *windowsTrayController) Start() error {
	t.mu.Lock()
	if t.started {
		t.mu.Unlock()
		return nil
	}
	t.started = true
	t.done = make(chan struct{})
	t.mu.Unlock()

	ready := make(chan error, 1)
	go t.runLoop(ready)

	select {
	case err := <-ready:
		if err != nil {
			t.mu.Lock()
			t.started = false
			t.ready = false
			t.mu.Unlock()
		}
		return err
	case <-time.After(2 * time.Second):
		t.mu.Lock()
		t.started = false
		t.ready = false
		t.mu.Unlock()
		return fmt.Errorf("tray init timeout")
	}
}

func (t *windowsTrayController) IsReady() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.ready
}

func (t *windowsTrayController) Stop() {
	t.mu.Lock()
	hwnd := t.hwnd
	done := t.done
	started := t.started
	t.mu.Unlock()
	if !started {
		return
	}

	if hwnd != 0 {
		_, _, _ = procPostMessageW.Call(uintptr(hwnd), wmClose, 0, 0)
	}

	if done != nil {
		select {
		case <-done:
		case <-time.After(1200 * time.Millisecond):
		}
	}

	t.mu.Lock()
	t.started = false
	t.ready = false
	t.mu.Unlock()
}

func (t *windowsTrayController) runLoop(ready chan<- error) {
	goruntime.LockOSThread()
	defer goruntime.UnlockOSThread()

	var hwnd windows.Handle
	var added bool
	defer func() {
		if added {
			t.removeIcon(hwnd)
		}
		if hwnd != 0 {
			trayByHwnd.Delete(uintptr(hwnd))
			_, _, _ = procDestroyWindow.Call(uintptr(hwnd))
		}

		t.mu.Lock()
		t.hwnd = 0
		t.ready = false
		t.started = false
		done := t.done
		t.mu.Unlock()
		if done != nil {
			close(done)
		}
	}()

	className := windows.StringToUTF16Ptr(t.className)
	hInstance, _, _ := procGetModuleHandleW.Call(0)
	wc := winWNDCLASSEX{
		CbSize:        uint32(unsafe.Sizeof(winWNDCLASSEX{})),
		LpfnWndProc:   trayWndProc,
		HInstance:     windows.Handle(hInstance),
		LpszClassName: className,
	}

	classAtom, _, classErr := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))
	if classAtom == 0 {
		if errno, ok := classErr.(syscall.Errno); !ok || errno != 1410 {
			ready <- fmt.Errorf("RegisterClassExW failed: %v", classErr)
			return
		}
	}

	windowName := windows.StringToUTF16Ptr("Netch Go Tray")
	h, _, createErr := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0,
		0, 0, 0, 0,
		0,
		0,
		hInstance,
		0,
	)
	if h == 0 {
		ready <- fmt.Errorf("CreateWindowExW failed: %v", createErr)
		return
	}
	hwnd = windows.Handle(h)
	trayByHwnd.Store(uintptr(hwnd), t)

	t.mu.Lock()
	t.hwnd = hwnd
	t.mu.Unlock()

	if err := t.addIcon(hwnd); err != nil {
		ready <- err
		return
	}
	added = true

	t.mu.Lock()
	t.ready = true
	t.mu.Unlock()
	ready <- nil

	for {
		var message winMSG
		ret, _, err := procGetMessageW.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		switch int32(ret) {
		case -1:
			return
		case 0:
			return
		default:
			_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&message)))
			_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&message)))
		}
		_ = err
	}
}

func (t *windowsTrayController) addIcon(hwnd windows.Handle) error {
	icon, own := t.loadPreferredIcon()

	nid := notifyIconData{
		CbSize:           uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:             hwnd,
		UID:              trayIconID,
		UFlags:           nifMessage | nifIcon | nifTip,
		UCallbackMessage: wmTrayCallback,
		HIcon:            windows.Handle(icon),
	}
	copy(nid.SzTip[:], windows.StringToUTF16("Netch Go"))

	ret, _, err := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		return fmt.Errorf("Shell_NotifyIconW NIM_ADD failed: %v", err)
	}

	nid.UTimeoutOrVersion = notifyIconVersion4
	_, _, _ = procShellNotifyIconW.Call(nimSetVersion, uintptr(unsafe.Pointer(&nid)))
	t.mu.Lock()
	t.icon = windows.Handle(icon)
	t.iconOwn = own
	t.mu.Unlock()
	return nil
}

func (t *windowsTrayController) removeIcon(hwnd windows.Handle) {
	nid := notifyIconData{
		CbSize: uint32(unsafe.Sizeof(notifyIconData{})),
		HWnd:   hwnd,
		UID:    trayIconID,
	}
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))

	t.mu.Lock()
	icon := t.icon
	iconOwn := t.iconOwn
	t.icon = 0
	t.iconOwn = false
	t.mu.Unlock()
	if iconOwn && icon != 0 {
		_, _, _ = procDestroyIcon.Call(uintptr(icon))
	}
}

func (t *windowsTrayController) loadPreferredIcon() (windows.Handle, bool) {
	for _, iconPath := range t.iconCandidates() {
		ptr, err := windows.UTF16PtrFromString(iconPath)
		if err != nil {
			continue
		}
		h, _, _ := procLoadImageW.Call(
			0,
			uintptr(unsafe.Pointer(ptr)),
			imageIcon,
			0,
			0,
			lrLoadFromFile|lrDefaultSize,
		)
		if h != 0 {
			return windows.Handle(h), true
		}
	}

	if icon, ok := loadIconFromExecutable(); ok {
		return icon, true
	}

	h, _, _ := procLoadIconW.Call(0, idiApplication)
	return windows.Handle(h), false
}

func (t *windowsTrayController) iconCandidates() []string {
	root := filepath.Clean(t.app.paths.RootDir)
	if root == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(root, "icon.ico"),
		filepath.Join(root, "build", "windows", "icon.ico"),
	}
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if iconFileExists(candidate) {
			result = append(result, candidate)
		}
	}
	return result
}

func iconFileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func loadIconFromExecutable() (windows.Handle, bool) {
	exePath, err := os.Executable()
	if err != nil {
		return 0, false
	}
	ptr, err := windows.UTF16PtrFromString(exePath)
	if err != nil {
		return 0, false
	}

	var large windows.Handle
	var small windows.Handle
	ret, _, _ := procExtractIconExW.Call(
		uintptr(unsafe.Pointer(ptr)),
		0,
		uintptr(unsafe.Pointer(&large)),
		uintptr(unsafe.Pointer(&small)),
		1,
	)
	if ret == 0 {
		return 0, false
	}

	if small != 0 {
		if large != 0 && large != small {
			_, _, _ = procDestroyIcon.Call(uintptr(large))
		}
		return small, true
	}
	if large != 0 {
		return large, true
	}
	return 0, false
}

func trayWindowProc(hwnd, msg, wParam, lParam uintptr) uintptr {
	if value, ok := trayByHwnd.Load(hwnd); ok {
		if tray, ok := value.(*windowsTrayController); ok {
			if handled, result := tray.handleMessage(uint32(msg), wParam, lParam); handled {
				return result
			}
		}
	}
	result, _, _ := procDefWindowProcW.Call(hwnd, msg, wParam, lParam)
	return result
}

func (t *windowsTrayController) handleMessage(msg uint32, wParam, lParam uintptr) (bool, uintptr) {
	switch msg {
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return true, 0
	case wmCommand:
		switch uint16(wParam & 0xffff) {
		case trayMenuShow:
			go t.app.showWindowFromTray()
			return true, 0
		case trayMenuHide:
			go t.app.hideWindowFromTray()
			return true, 0
		case trayMenuExit:
			go t.app.requestQuitFromTray()
			return true, 0
		}
	case wmTrayCallback:
		// NOTIFYICON_VERSION_4 uses LOWORD(lParam) as notification code.
		notification := uint32(loword(lParam))
		switch notification {
		case wmLButtonUp, wmLButtonDblClk:
			go t.app.showWindowFromTray()
			return true, 0
		case wmRButtonUp, wmContextMenu:
			t.showMenu()
			return true, 0
		}
	}
	return false, 0
}

func (t *windowsTrayController) showMenu() {
	t.mu.Lock()
	hwnd := t.hwnd
	t.mu.Unlock()
	if hwnd == 0 {
		return
	}

	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer func() {
		_, _, _ = procDestroyMenu.Call(menu)
	}()

	showText := windows.StringToUTF16Ptr("显示主窗口")
	hideText := windows.StringToUTF16Ptr("隐藏到托盘")
	exitText := windows.StringToUTF16Ptr("退出")
	_, _, _ = procAppendMenuW.Call(menu, mfString, trayMenuShow, uintptr(unsafe.Pointer(showText)))
	_, _, _ = procAppendMenuW.Call(menu, mfString, trayMenuHide, uintptr(unsafe.Pointer(hideText)))
	_, _, _ = procAppendMenuW.Call(menu, mfString, trayMenuExit, uintptr(unsafe.Pointer(exitText)))

	var pt winPoint
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	_, _, _ = procSetForegroundWindow.Call(uintptr(hwnd))
	_, _, _ = procTrackPopupMenu.Call(menu, tpmRightButton, uintptr(pt.X), uintptr(pt.Y), 0, uintptr(hwnd), 0)
	_, _, _ = procPostMessageW.Call(uintptr(hwnd), wmNull, 0, 0)
}

func loword(value uintptr) uint16 {
	return uint16(value & 0xffff)
}
