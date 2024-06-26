#include <stdio.h>
#include <ogc/consol.h>

#include "config.h"
#include "tools.h"
#include "menu.h"

void DrawHeading(void)
{
    int conX, conY;
    CON_GetMetrics(&conX, &conY);

    // Draw a nice heading.
    puts("cdbackup mod " VERSION ", by thepikachugamer, modded by Larsenv");
    puts("Backup/restore/export your Wii Message Board data.");
    for (int i = 0; i < conX; i++)
        putchar(0xcd);
}

int MainMenu(int argc; MainMenuItem argv[argc], int argc)
{

    int x = 0;
    while (true)
    {
        MainMenuItem *item = argv + x;

        clear();
        DrawHeading();
        for (MainMenuItem *i = argv; i < argv + argc; i++)
        {
            if (i == item)
                printf("%s>>  %s\x1b[40m\x1b[39m\n", i->highlight_str, i->name);
            else
                printf("    %s\n", i->name);
        }

        while (true)
        {
            input_scan();

            if (input_pressed(up))
            {
                if (x-- == 0)
                    x = argc - 1;
                break;
            }
            else

                if (input_pressed(down))
            {
                if (++x == argc)
                    x = 0;
                break;
            }
            else

                if (input_pressed(a))
            {
                if (!item->action)
                    return 0;

                clear();
                DrawHeading();
                item->action();

                puts("\nPress any button to continue...");
                do
                    input_scan();
                while (!input_btns);

                clear();
                break;
            }
            else

                if (input_pressed(b) || input_pressed(home))
            {
                return 0;
            }
        }
    }

    return 0;
}
