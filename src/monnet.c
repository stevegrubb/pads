/*************************************************************************
 *
 * monnet.c
 *
 * Matt Shelton <matt@mattshelton.com>
 *
 * This module contains function related to the storage and retrieval of
 * monitored networks.  PADS will take a linked list of monitored networks
 * and determine whether or not an IP address falls within the network.
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
 * $Id: monnet.c,v 1.3 2005/02/17 16:29:14 mattshelton Exp $
 *
 **************************************************************************/
#include <stdlib.h>
#include <arpa/inet.h>
#include "monnet.h"
#include "util.h"

static struct mon_net *mn = NULL;

/* ----------------------------------------------------------
 * FUNCTION	: parse_networks
 * DESCRIPTION	: This function will parse the input from the
 *		: '-n' switch and place it into a data
 *		: structure.  This input will be formated in
 *		: the following format:
 *			192.168.0.0/24,10.10.10.0/16
 * INPUT	: 0 - Raw Input
 * RETURN	: None!
* ---------------------------------------------------------- */
void parse_networks (char *cmdline)
{
    int i = 0;
    char network[16], netmask[3], tmp[16];

    /* Make sure something was defined. */
    if (cmdline == NULL)
	return;

    /* Parse Line */
    for (;;) {
	/* End of Network */
	if (*cmdline == '/') {
	    tmp[i] = '\0';
	    strlcpy(network, tmp, sizeof(network));
	    tmp[0] = '\0';
	    i = 0;

	} else if (*cmdline == ' ') {
	    /* Do nothing, just skip the space. */

	/* End of Netmask, process string. */
	} else if (*cmdline == ',' || *cmdline == '\0') {
	    tmp[i] = '\0';
	    strlcpy(netmask, tmp, sizeof(netmask));
	    tmp[0] = '\0';
	    i = 0;

	    /* Add to monnet data structure. */
	    add_monnet(network, netmask);

	    /* Exit if it's the end of the string. */
	    if (*cmdline =='\0')
		break;
	} else {
	    tmp[i] = *cmdline;
	    i++;
	}

	cmdline++;
    }
}

static unsigned int netmasks[33] = {
    0x0,
    0x80000000,
    0xC0000000,
    0xE0000000,
    0xF0000000,
    0xF8000000,
    0xFC000000,
    0xFE000000,
    0xFF000000,
    0xFF800000,
    0xFFC00000,
    0xFFE00000,
    0xFFF00000,
    0xFFF80000,
    0xFFFC0000,
    0xFFFE0000,
    0xFFFF0000,
    0xFFFF8000,
    0xFFFFC000,
    0xFFFFE000,
    0xFFFFF000,
    0xFFFFF800,
    0xFFFFFC00,
    0xFFFFFE00,
    0xFFFFFF00,
    0xFFFFFF80,
    0xFFFFFFC0,
    0xFFFFFFE0,
    0xFFFFFFF0,
    0xFFFFFFF8,
    0xFFFFFFFC,
    0xFFFFFFFE,
    0xFFFFFFFF,
};

/* ----------------------------------------------------------
 * FUNCTION	: add_monnet
 * DESCRIPTION	: This function will add a monitored network
 *		: record to the specified data structure.
 * INPUT	: 0 - (char *) Network
 *		: 1 - (char *) Netmask
 * RETURN	: None!
 * ---------------------------------------------------------- */
void add_monnet(char *network, char *netmask)
{
    struct mon_net *rec, *data;
    struct in_addr net_addr;
    int nmask;

    nmask = atoi(netmask);

    /* Ensure that the netmask is correct. */
    if (nmask < 1 && nmask > 32)
	return;

    /* Ensure that the network is correct. */
    if ((inet_aton(network, &net_addr)) != 1)
	return;

    /* Create structure array and assign data to it. */
    rec = (struct mon_net*)malloc(sizeof(struct mon_net));
    rec->netmask = htonl(netmasks[nmask]);
    rec->network = ((unsigned long) net_addr.s_addr & rec->netmask);
    rec->next = NULL;

    /* Find position within array and assign new data to it. */
    if (mn == NULL) {
	mn = rec;
    } else {
	data = mn;
	while (data != NULL) {
	    if (data->next == NULL) {
		data->next = rec;
		break;
	    } else {
		data = data->next;
	    }
	}
    }
}

/* ----------------------------------------------------------
 * FUNCTION	: check_monnet
 * DESCRIPTION	: This function will check to see whether a
 *		: specified IP address falls within the list
 *		: of monitored networks.
 * INPUT	: 0 - IP Address
 * RETURN	: 0 - No, skip asset
 *		: 1 - Yes, process asset
 * ---------------------------------------------------------- */
short check_monnet (const struct in_addr ip_addr)
{
    struct mon_net *data;

    if (mn == NULL) {
	/* No monitored networks */
	return 1;
    } else {
	/* Go through monitored networks. */
	data = mn;

	while (data != NULL) {
	    if ((ip_addr.s_addr & data->netmask) == data->network) {
		/* Found! */
		return 1;
	    } else {
		data = data->next;
	    }
	}
    }

    /* Asset does not fall within a monitored network. */
    return 0;
}

/* ----------------------------------------------------------
 * FUNCTION     : end_monnet
 * DESCRIPTION  : This function will free all the records
 *              : placed in the monnet data structure.
 * INPUT        : None!
 * RETURN       : None!
 * ---------------------------------------------------------- */
void end_monnet (void)
{
    struct mon_net *next;

    /* Free records in monnet list (mn). */
    while (mn != NULL) {
        next = mn->next;
        free (mn);
        mn = next;
    }
}

