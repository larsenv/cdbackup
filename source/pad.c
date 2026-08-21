#include <unistd.h>
#include <gccore.h>
#include <ogc/pad.h>
#include <wiikeyboard/usbkeyboard.h>
#ifdef HAVE_WIIDRC
#include <wiidrc/wiidrc.h>
#endif
#ifdef HAVE_WUPC
#include <wupc/wupc.h>
#endif
#ifdef HAVE_SICKSAXIS
#include <sicksaxis.h>
#endif

#include "pad.h"

static uint32_t pad_buttons;
#ifdef HAVE_SICKSAXIS
static struct ss_device ds3;
static bool ds3_initialized;
static uint32_t ds3_previous;
#endif

static uint32_t map_classic(uint32_t buttons)
{
	uint32_t out = 0;
	if (buttons & (WPAD_CLASSIC_BUTTON_ZR | WPAD_CLASSIC_BUTTON_PLUS)) out |= WPAD_BUTTON_PLUS;
	if (buttons & (WPAD_CLASSIC_BUTTON_ZL | WPAD_CLASSIC_BUTTON_MINUS)) out |= WPAD_BUTTON_MINUS;
	if (buttons & WPAD_CLASSIC_BUTTON_A) out |= WPAD_BUTTON_A;
	if (buttons & WPAD_CLASSIC_BUTTON_B) out |= WPAD_BUTTON_B;
	if (buttons & WPAD_CLASSIC_BUTTON_X) out |= WPAD_BUTTON_1;
	if (buttons & WPAD_CLASSIC_BUTTON_Y) out |= WPAD_BUTTON_2;
	if (buttons & WPAD_CLASSIC_BUTTON_HOME) out |= WPAD_BUTTON_HOME;
	if (buttons & WPAD_CLASSIC_BUTTON_UP) out |= WPAD_BUTTON_UP;
	if (buttons & WPAD_CLASSIC_BUTTON_DOWN) out |= WPAD_BUTTON_DOWN;
	if (buttons & WPAD_CLASSIC_BUTTON_LEFT) out |= WPAD_BUTTON_LEFT;
	if (buttons & WPAD_CLASSIC_BUTTON_RIGHT) out |= WPAD_BUTTON_RIGHT;
	return out;
}

#ifdef HAVE_WIIDRC
static uint32_t map_drc(uint32_t buttons)
{
	uint32_t out = 0;
	if (buttons & (WIIDRC_BUTTON_R | WIIDRC_BUTTON_ZR | WIIDRC_BUTTON_PLUS)) out |= WPAD_BUTTON_PLUS;
	if (buttons & (WIIDRC_BUTTON_L | WIIDRC_BUTTON_ZL | WIIDRC_BUTTON_MINUS)) out |= WPAD_BUTTON_MINUS;
	if (buttons & WIIDRC_BUTTON_A) out |= WPAD_BUTTON_A;
	if (buttons & WIIDRC_BUTTON_B) out |= WPAD_BUTTON_B;
	if (buttons & WIIDRC_BUTTON_X) out |= WPAD_BUTTON_1;
	if (buttons & WIIDRC_BUTTON_Y) out |= WPAD_BUTTON_2;
	if (buttons & WIIDRC_BUTTON_HOME) out |= WPAD_BUTTON_HOME;
	if (buttons & WIIDRC_BUTTON_UP) out |= WPAD_BUTTON_UP;
	if (buttons & WIIDRC_BUTTON_DOWN) out |= WPAD_BUTTON_DOWN;
	if (buttons & WIIDRC_BUTTON_LEFT) out |= WPAD_BUTTON_LEFT;
	if (buttons & WIIDRC_BUTTON_RIGHT) out |= WPAD_BUTTON_RIGHT;
	return out;
}
#endif

#ifdef HAVE_SICKSAXIS
static uint32_t poll_ds3(void)
{
	if (!ds3_initialized) return 0;
	if (!ss_is_connected(&ds3)) {
		ds3_previous = 0;
		if (ss_open(&ds3) > 0) ss_start_reading(&ds3);
		else return 0;
	}
	const struct SS_BUTTONS *b = &ds3.pad.buttons;
	uint32_t held = 0;
	if (b->start || b->R1 || b->R2) held |= WPAD_BUTTON_PLUS;
	if (b->select || b->L1 || b->L2) held |= WPAD_BUTTON_MINUS;
	if (b->cross) held |= WPAD_BUTTON_A;
	if (b->circle) held |= WPAD_BUTTON_B;
	if (b->square) held |= WPAD_BUTTON_1;
	if (b->triangle) held |= WPAD_BUTTON_2;
	if (b->PS) held |= WPAD_BUTTON_HOME;
	if (b->up) held |= WPAD_BUTTON_UP;
	if (b->down) held |= WPAD_BUTTON_DOWN;
	if (b->left) held |= WPAD_BUTTON_LEFT;
	if (b->right) held |= WPAD_BUTTON_RIGHT;
	uint32_t down = held & ~ds3_previous;
	ds3_previous = held;
	return down;
}
#endif

/* USB Keyboard stuffs */
static lwp_t kbd_thread_hndl = LWP_THREAD_NULL;
static volatile bool kbd_thread_should_run = false;
static uint32_t kbd_buttons;

// from Priiloader (/tools/Dacoslove/source/Input.cpp (!?))
void KBEventHandler(USBKeyboard_event event)
{
	if (event.type != USBKEYBOARD_PRESSED && event.type != USBKEYBOARD_RELEASED)
		return;

	uint32_t button = 0;

	switch (event.keyCode)
	{
	case 0x52: // Up
		button = WPAD_BUTTON_UP;
		break;
	case 0x51: // Down
		button = WPAD_BUTTON_DOWN;
		break;
	case 0x50: // Left
		button = WPAD_BUTTON_LEFT;
		break;
	case 0x4F: // Right
		button = WPAD_BUTTON_RIGHT;
		break;
	case 0x28: // Enter
	case 0x58: // Enter (Numpad)
		button = WPAD_BUTTON_A;
		break;
	case 0x2A: // Backspace
		button = WPAD_BUTTON_B;
		break;
	case 0x1B: // X
		button = WPAD_BUTTON_1;
		break;
	case 0x1C: // Y
		button = WPAD_BUTTON_2;
		break;
	case 0x4C: // Delete
		button = WPAD_BUTTON_MINUS;
		break;
	case 0x29: // ESC
	case 0x4A: // Home
		button = WPAD_BUTTON_HOME;
		break;

	default:
		break;
	}

	if (event.type == USBKEYBOARD_PRESSED)
		kbd_buttons |= button;
	else
		kbd_buttons &= ~button;
}

void *kbd_thread(void *userp)
{
	while (kbd_thread_should_run)
	{
		if (!USBKeyboard_IsConnected() && USBKeyboard_Open(KBEventHandler))
		{
			for (int i = 0; i < 3; i++)
			{
				USBKeyboard_SetLed(i, 1);
				usleep(250000);
			}
		}

		USBKeyboard_Scan();
		usleep(400);
	}

	return NULL;
}

void initpads()
{
#ifdef HAVE_WUPC
	WUPC_Init();
#endif
	WPAD_Init();
	PAD_Init();
	USB_Initialize();
	USBKeyboard_Initialize();
#ifdef HAVE_WIIDRC
	WiiDRC_Init();
#endif
#ifdef HAVE_SICKSAXIS
	if (ss_init() >= 0 && ss_initialize(&ds3) >= 0) {
		ds3_initialized = true;
		if (ss_open(&ds3) > 0) ss_start_reading(&ds3);
	}
#endif

	kbd_thread_should_run = true;
	LWP_CreateThread(&kbd_thread_hndl, kbd_thread, 0, 0, 0x4000, 0x7F);
}

void scanpads()
{
	uint32_t buttons = 0;
	pad_buttons = 0;
#ifdef HAVE_WUPC
	WUPC_UpdateButtonStats();
	for (int chan = 0; chan < 4; chan++) buttons |= WUPC_ButtonsDown(chan);
	pad_buttons |= map_classic(buttons);
#endif
	buttons = 0;
	WPAD_ScanPads();
	for (int chan = 0; chan < 4; chan++) buttons |= WPAD_ButtonsDown(chan);
	pad_buttons |= buttons | map_classic(buttons);
#ifdef HAVE_WIIDRC
	if (WiiDRC_Inited() && WiiDRC_Connected() && WiiDRC_ScanPads())
		pad_buttons |= map_drc(WiiDRC_ButtonsDown());
#endif
#ifdef HAVE_SICKSAXIS
	pad_buttons |= poll_ds3();
#endif
	PAD_ScanPads();
	u16 gcn_down = 0;
	for (int chan = 0; chan < 4; chan++) gcn_down |= PAD_ButtonsDown(chan);

	pad_buttons |= kbd_buttons;
	kbd_buttons = 0;
	if (SYS_ResetButtonDown())
		pad_buttons |= WPAD_BUTTON_HOME;

	if (gcn_down & PAD_BUTTON_A)
		pad_buttons |= WPAD_BUTTON_A;
	if (gcn_down & PAD_BUTTON_B)
		pad_buttons |= WPAD_BUTTON_B;
	if (gcn_down & PAD_BUTTON_X)
		pad_buttons |= WPAD_BUTTON_1;
	if (gcn_down & PAD_BUTTON_Y)
		pad_buttons |= WPAD_BUTTON_2;
	if (gcn_down & PAD_BUTTON_START)
		pad_buttons |= WPAD_BUTTON_HOME | WPAD_BUTTON_PLUS;
	if (gcn_down & PAD_BUTTON_UP)
		pad_buttons |= WPAD_BUTTON_UP;
	if (gcn_down & PAD_BUTTON_DOWN)
		pad_buttons |= WPAD_BUTTON_DOWN;
	if (gcn_down & PAD_BUTTON_LEFT)
		pad_buttons |= WPAD_BUTTON_LEFT;
	if (gcn_down & PAD_BUTTON_RIGHT)
		pad_buttons |= WPAD_BUTTON_RIGHT;
}

void stoppads()
{
#ifdef HAVE_SICKSAXIS
	if (ds3_initialized) {
		if (ss_is_connected(&ds3)) ss_stop_reading(&ds3);
		ss_close(&ds3);
	}
#endif
#ifdef HAVE_WUPC
	WUPC_Shutdown();
#endif
	WPAD_Shutdown();

	kbd_thread_should_run = false;
	usleep(400);
	USBKeyboard_Close();
	USBKeyboard_Deinitialize();
	if (kbd_thread_hndl != LWP_THREAD_NULL)
		LWP_JoinThread(kbd_thread_hndl, 0);

	kbd_thread_hndl = LWP_THREAD_NULL;
}

uint32_t wait_button(uint32_t button)
{
	scanpads();
	while (!(pad_buttons & (button ? button : ~0)))
		scanpads();

	return pad_buttons & (button ? button : ~0);
}

uint32_t buttons_down(uint32_t button)
{
	return pad_buttons & (button ? button : ~0);
}
