/*************************************************************************
 * output-fifo.c
 *
 * Matt Shelton	<matt@mattshelton.com>
 *
 * This output module will write data to a FIFO named pipe.  This will
 * allow external applications access to PADS data in real-time.
 *
 * Copyright (C) 2004 Matt Shelton <matt@mattshelton.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * $Id: output-fifo.c,v 1.6 2005/02/22 16:09:25 mattshelton Exp $
 *
 **************************************************************************/
#include <arpa/inet.h>
#include "output-fifo.h"
#include "util.h"

/*
 * MODULE NOTES
 *
 * This module will write asset data to a FIFO special file.  This will
 * separate the detection engine from the IO module and increase the
 * overall speed of the system.
 *
 * Output written to the FIFO will be in comma separated format and will
 * begin with an action_id field.  This field will allow different types
 * of output to be written to the FIFO.
 *
 * action_id		action
 * 01			TCP / ICMP Asset Discovered
 * 02			ARP Asset Discovered
 * 03			TCP / ICMP Statistic Information
 *
 * The following lines contains an example of the data written to the
 * FIFO:
 *
 * 01,10.10.10.83,22,6,ssh,OpenSSH 3.8.1 (Protocol 2.0),1100846817
 * 02,10.10.10.81,3Com 3CRWE73796B,00:50:da:5a:2d:ae,1100846817
 * 03,10.10.10.83,22,6,1100847309
 *
 */

OutputFIFOConf output_fifo_conf;

/* ----------------------------------------------------------
 * FUNCTION	: setup_output_fifo
 * DESCRIPTION	: This function will register the output
 *		: plugin.
 * INPUT	: None!
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
setup_output_fifo (void)
{
    OutputPlugin *plugin;

    /* Allocate and setup plugin data record. */
    plugin = (OutputPlugin*)malloc(sizeof(OutputPlugin));
    plugin->name = bfromcstr("fifo");
    plugin->init = init_output_fifo;
    plugin->print_asset = print_asset_fifo;
    plugin->print_arp = print_arp_asset_fifo;
    plugin->print_stat = print_stat_fifo;
    plugin->end = end_output_fifo;

    /* Register plugin with input module. */
    if ((register_output_plugin(plugin)) == -1) {
	if (plugin != NULL)
	    free(plugin);
	log_message("warning:  'register_output_plugin' in function 'setup_output_fifo' failed.");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: init_output_fifo
 * DESCRIPTION	: This function will initialize the FIFO
 *		: file.
 * INPUT	: 0 - FIFO filename
 * RETURN	: 0 success, -1 failure
 * --------------------------------------------------------- */
int
init_output_fifo (bstring fifo_file)
{
    verbose_message("Initializing FIFO output plugin.");

    /* Make sure report_file isn't NULL. */
    if (fifo_file == NULL)
	fifo_file = bfromcstr("pads.fifo");

    output_fifo_conf.filename = bstrcpy(fifo_file);

    mkfifo ((char *)bdata(fifo_file), 0755);

    verbose_message("Open FIFO File\n");
    if ((output_fifo_conf.file = fopen((char*)bdata(fifo_file), "w+")) == NULL){
	err_message("Unable to open FIFO file (%s)!\n", bdata(fifo_file));
        return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_asset_fifo
 * DESCRIPTION	: This function will print an asset to the
 *		: FIFO file.
 * INPUT	: 0 - Port
 *		: 1 - IP  Address
 *		: 2 - Protocol
 *		: 3 - Service
 *		: 4 - Application
 *		: 5 - Discovered
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_asset_fifo (Asset *rec)
{
    if (output_fifo_conf.file != NULL) {
	if (gc.hide_unknowns == 0 || ((biseq(rec->service, bfromcstr("unknown")) != 0) &&
		    (biseq(rec->application, bfromcstr("unknown")) != 0))) {
	    fprintf(output_fifo_conf.file, "01,%s,%d,%d,%s,%s,%d\n",
			inet_ntoa(rec->ip_addr), ntohs(rec->port), rec->proto,
			bdata(rec->service), bdata(rec->application),
			(int)rec->discovered);
	    fflush(output_fifo_conf.file);
	}
    } else {
	fprintf(stderr, "[!] ERROR:  File handle not open!\n");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_arp_asset_fifo
 * DESCRIPTION	: This function will print an ARP asset to
 *		: the FIFO file.
 * INPUT	: 0 - IP Address
 *		: 1 - MAC Address
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_arp_asset_fifo (ArpAsset *rec)
{
    /* Print to File */
    if (output_fifo_conf.file != NULL) {
	if (rec->mac_resolved != NULL) {
	    fprintf(output_fifo_conf.file, "02,%s,%s,%s,%d\n",
		inet_ntoa(rec->ip_addr), bdata(rec->mac_resolved),
		 hex2mac(rec->mac_addr), (int)rec->discovered);
	} else {
	    fprintf(output_fifo_conf.file, "02,%s,unknown,%s,%d\n",
			inet_ntoa(rec->ip_addr), hex2mac(rec->mac_addr),
			(int)rec->discovered);
	}

	fflush(output_fifo_conf.file);
    } else {
	fprintf(stderr, "[!] ERROR:  File handle not open!\n");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: print_stat_fifo
 * DESCRIPTION	: This function will print statistic
 *		: information to the FIFO file.
 * INPUT	: 0 - IP Address
 *		: 1 - Port
 *		: 2 - Protocol
 * RETURN	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
print_stat_fifo (Asset *rec)
{
    if (output_fifo_conf.file != NULL) {
	fprintf(output_fifo_conf.file, "03,%s,%d,%d,%d\n",
		inet_ntoa(rec->ip_addr), ntohs(rec->port), rec->proto,
		(int)time(NULL));
	fflush(output_fifo_conf.file);

    } else {
	fprintf(stderr, "[!] ERROR:  File handle not open!\n");
	return -1;
    }

    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION	: end_output_fifo
 * DESCRIPTION	: This function will free the memory declared
 *		: by the fifo output module.
 * INPUT	: None
 * OUTPUT	: 0 - Success
 *		: -1 - Error
 * ---------------------------------------------------------- */
int
end_output_fifo ()
{
    verbose_message("Ending CSV Output Plugin.");

    verbose_message("Closing FIFO File.");
    fclose(output_fifo_conf.file);

    /* Clean Up */
    if (output_fifo_conf.filename)
	bdestroy(output_fifo_conf.filename);

    return 0;
}

