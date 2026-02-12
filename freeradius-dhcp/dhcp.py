# Authors:
#   Rob Crittenden <rcritten@redhat.com>
#   Pavel Zuna <pzuna@redhat.com>
#   Charles Hedrick <hedrick@rutgers.edu>
#
# Copyright (C) 2009  Red Hat, 2019, Rutgers University
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from ipalib.plugable import Registry
from .baseldap import (
    LDAPObject,
    LDAPCreate,
    LDAPDelete,
    LDAPUpdate,
    LDAPSearch,
    LDAPRetrieve,
    LDAPAddMember,
    LDAPAddAttribute,
    LDAPRemoveAttribute,
    LDAPRemoveMember,
    LDAPQuery,
    LDAPAddReverseMember,
    global_output_params,
    pkey_to_value,
    entry_to_dict,
    LDAPRemoveReverseMember)
from ipalib import api, Flag, Str, _, ngettext, errors
from ipalib import output
from ipapython.dn import DN
import re
import ipaddress
import socket
import string
import tempfile
import os
import subprocess

__doc__ = _("""
 DHCP
""")

register = Registry()

topic = 'dhcp'

def test_ipaddress(item, errors):
    item = item.strip()
    try:
        n = socket.inet_aton(item)
        return item
    except:
        errors.append(f'{item} is not a valid IP address')
        return None
    
def test_iplist(item, errors):
    item = item.strip()
    items = item.split(',')
    ret = ""
    for i in range(len(items)):
        addr = items[i]
        addr = test_ipaddress(addr, errors)
        if addr is None:
            return None
        if i == 0:
            ret = addr
        else:
            ret = f'{ret},{addr}'
    return ret

def test_quotedstring(item, errors):
    item = item.strip()
    if item[0] != '"' or item[-1] != '"':
        errors.append(f'item must be quoted string')
        return None
    return item

def test_quotedstringlist(item, errors):
    item = item.strip()
    if item[0] != '"':
        errors.append(f'item has no value')
        return None

    ret = ''
    # can't just split on , because string might have
    #  a comma in it.
    # we don't currently support escaped quotes in a string

    i = 0
    while item[i] == '"':
        j = item.find('"', i+1)
        if j < 0:
            errors.append(f'{item} missing end quota')
            return None
        if i == 0:
            ret = item[0:j+1]
        else:
            ret = f'{ret},{item[i:j+1]}'
        # have end of string. next had better be , or end
        j += 1
        # skip spaces
        while j < len(item) and item[j] == ' ':
            j += 1
        # if no more, return
        if j == len(item):
            return ret
        if item[j] != ',':
            errors.append(f'{item} commas must separate items')
        j += 1
        while j < len(item) and item[j] == ' ':
            j += 1        
        print(item[j:])
        if item[j] != '"':
            errors.append(f'{item} items must be quoted')
        i = j

def test_integer(item, errors):
    item = item.strip()
    try:
        int(item)
        return item
    except:
        errors.append(f'{item} must be an integer')
        return None

def test_string(item, errors):
    if item.find('"') >= 0:
        errors.append(f'{item} should not be quoted')
        return None
    return item.strip()

def test_stringlist(item, errors):
    if item.find('"') >= 0:
        errors.append(f'{item} should not be quoted')
        return None
    ret = None
    items = item.split(',')
    if len(items) == 0:
        errors.append(f'item must have a value')
        return None
    for i in range(len(items)):
        if i == 0:
            ret = items[0].strip()
        else:
            ret = f'{ret},{items[i].strip()}'
    return ret

option_tests = {"broadcast-address": test_iplist,
              "routers": test_iplist,
              "subnet-mask": test_ipaddress,
              "domain-name": test_quotedstring,
              "timeoffset": test_integer,
              "host-name": test_quotedstring,
              "tftp-server-name": test_quotedstring,
              "ntp-servers": test_stringlist,
              "time-servers": test_stringlist,
              "domain-search": test_quotedstringlist,
              "domain-name-servers": test_stringlist}

statement_tests = {"max-lease-time": test_integer,
              "fixed-address": test_ipaddress,
              "next-server": test_ipaddress,
              "filename": test_quotedstring}

def check_dhcp_item(item, tests, errors):
        
    item = item.strip()
    i = item.find(" ")
    if i < 0:
        errors.append(f"no value for {item}")
        return None
    value = item[i+1:].strip()
    attr = item[0:i]
    if attr not in tests:
        errors.append(f"{item} is not implemented")
        return None

    test = tests[attr]
    # value may be changed, e.g. by removing spaces
    value = test(value, errors)
    if value is None:
        print('value is none')
        return None
    return f'{attr} {value}'

# verify that a change isn't going to cause the dhcp server to fail to start
# write out the entry, and call dhcpd -t to test it. common code for all objects
def check_dhcp_entry(prefix, suffix, entry_attrs):
    errorlist = []
    if 'dhcpstatements' in entry_attrs:
        items = entry_attrs['dhcpstatements']
        for i in range(len(items)):
            item = items[i]
            item = check_dhcp_item(item, statement_tests, errorlist)
            if item is not None:
                items[i] = item
        entry_attrs['dhcpstatements'] = items
        
    if 'dhcpoption' in entry_attrs:
        items = entry_attrs['dhcpoption']
        for i in range(len(items)):
            item = items[i]
            item = check_dhcp_item(item, option_tests, errorlist)
            if item is not None:
                items[i] = item
        entry_attrs['dhcpoption'] = items

    if errorlist:
        error_text = ', '.join(map(str, errorlist))
        raise errors.ValidationError(
                name='syntax', error=_(error_text))

## checker for subnets
def dhcp_pre_callback_subnetmod(ldap, dn, entry_attrs):
       # in case user did something weird, get netmask from cidr spec. that's what
       # the dhcpd ldap code does
       c = None
       existing = ldap.get_entry(dn, ['cn', 'dhcpnetmask'])
       # these entries have to exist
       exist_cn = existing['cn'][0]
       exist_netmask = existing['dhcpnetmask'][0]

       # subnet yyy netmask {  - the netmask is built from from the netmask attribute.
       # this is completely separate from any netmask ooption. The opotion is sent to
       # the client, but has nothing to do with the mask here
       if 'dhcpnetmask' in entry_attrs and entry_attrs['dhcpnetmask'] is not None:
           # this is only set if we're changing the netmask
           c = entry_attrs['dhcpnetmask']
       else:
           c = exist_netmask

       # compute the netmask from the cidr size
       net = None
       try: 
           net = ipaddress.IPv4Network(_(str(exist_cn) + '/' + str(c)))
           entry_attrs['objectClass'] = ['top', 'dhcpSubnet', 'dhcpOptions', 'csRutgersEduDhcpAddresses']
           entry_attrs['csRutgersEduDhcpIpStart'] = int(net.network_address)
           entry_attrs['csRutgersEduDhcpIpEnd'] = int(net.broadcast_address)
       except ValueError:
            raise self.obj.handle_not_found('invalid address')

       # now we have the data to build the subnet yyy netmask {
       # that has to be there for a valid entry. We're not worried about
       # options and statements. Only those actually specified in this command
       # need to be checked
       check_dhcp_entry('subnet ' + str(exist_cn) + ' netmask ' + str(net.netmask) + '{', '}', entry_attrs);
       return dn

## checker for pools
def dhcp_pre_callback_pool(ldap, dn, entry_attrs):
        # required option
        subnet = dn[1].value
        subattrs = ldap.get_entry(dn[1:], ['dhcpnetmask'])
        if subattrs is None or subattrs['dhcpnetmask'] is None:
            raise self.obj.handle_not_found('subnet does not exists')
        # compute the netmask from the cidr size
        net = None
        try: 
            net = ipaddress.IPv4Network(_(subnet + '/' + str(subattrs['dhcpnetmask'][0])))
        except ValueError:
            raise errors.ValidationError(
                name='subnet', error=_('invalid subnet'))

        # range must be included. if we aren't changing it, it won't be
        # in entry_attrs, so get the range from the current entry
        # check_attrs is what to check. add range if it's not there
        check_attrs = entry_attrs
        if not 'dhcprange' in  entry_attrs:
            attrs = ldap.get_entry(dn, ['dhcprange'])            
            if not 'dhcprange' in attrs:
                raise errors.ValidationError(
                    name='range', error=_('pool has no range'))
            check_attrs = entry_attrs.copy()
            check_attrs['dhcprange'] = attrs['dhcprange']

        check_dhcp_entry('subnet ' + subnet + ' netmask ' + str(net.netmask) + '{\npool {', '}\n}', check_attrs);
        return dn

@register()
class dhcpconfig(LDAPObject):
    """
    DHCP object.
    """
    container_dn = DN(('ou', 'dhcp'))
    object_name = _('DHCP configuration')
    object_class = ['dhcpservice']
    default_attributes = ['cn', 'dhcpStatements', 'dhcpoption', 'dhcpcomments']
    allow_rename = False
    label = _('DHCP configuration')
    label_singular = _('DHCP configuration')
    takes_params = (
        Str('cn',
            cli_name='config',
            label=_('Config'),
            doc=_('DHCP Configuration - There should be just one, called "config".'),
            primary_key=True,
        ),
        Str('dhcpstatements*',
            cli_name='statements',
            label=_('Statements'),
            doc=_('A DHCP configuration statement other than option'),
        ),
        Str('dhcpoption*',
            cli_name='options',
            label=_('Options'),
            doc=_('A DHCP configuration option'),
        ),
        Str('dhcpcomments?',
            cli_name='comment',
            label=_('Comment'),
            doc=_('A DHCP comment'),
        ),
        Flag('increment?',
            cli_name='increment',
            label=_('increment'),
            doc=_('Increment serial number - causes the servers to restart'),
            flags=['virtual_attribute'],
         ),

    )


@register()
class dhcpconfig_mod(LDAPUpdate):
    __doc__ = _('Modify DHCP configuration. Do not use for options or statements unless you want to replace all of them at once. A single argument of "config" must be supplied before the options.')

    # implement the increment option
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # the option is just the ethernet address, but the LDAP attr has "ethernet " prefix
        if 'increment' in options:
            attrs = ldap.find_entry_by_attr('cn', keys[0], 'dhcpservice', ['dhcpcomments'], dn[1:])
            if 'dhcpcomments' in attrs:
                entry_attrs['dhcpcomments'] = str(int(attrs['dhcpcomments'][0]) + 1)
        check_dhcp_entry('', '', entry_attrs);
        return entry_attrs.dn
    
    msg_summary = _('Modified DHCP configuration "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpconfig_add_option(LDAPAddAttribute):
    __doc__ = _('Add a DHCP top-level option. The first argument must be "config", followed by the option to be added. It is Normally a quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('', '', entry_attrs)
        return dn

    msg_summary = _('Modified DHCP configuration "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')
    
@register()
class dhcpconfig_remove_option(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP top-level option. The first argument must be "config", followed by the option to be removed. It is Normally a quoted pair: "keyword value"')

    attribute = 'dhcpoption'

    msg_summary = _('Modified DHCP configuration "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')


@register()
class dhcpconfig_add_statement(LDAPAddAttribute):
    __doc__ = _('Add a DHCP top-level statement. The first argument must be "config", followed by the statement to be added. It is Normally a quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    def _update_attrs(self, update, entry_attrs):
        check_dhcp_entry(None, None, entry_attrs)
        return super(_update_attrs(self, update, entry_attrs))

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('', '', entry_attrs)
        return dn

    msg_summary = _('Modified DHCP configuration "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')


@register()
class dhcpconfig_remove_statement(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP top-level statement. The first argument must be "config", followed by the statement to be removed. It is Normally a quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    msg_summary = _('Modified DHCP configuration "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpconfig_show(LDAPRetrieve):
    __doc__ = _('Display information about DHCP configuration. A single argument "config" must always be used')

@register()
class dhcphost(LDAPObject):
    """
    DHCP object.
    """
        
    container_dn = DN(('cn', 'config'), ('ou', 'dhcp'))
    object_name = _('DHCP host')
    object_class = ['dhcphost']
    default_attributes = ['cn', 'dhcpstatements', 'dhcpoption', 'dhcpcomments', 'dhcphwaddress', 'ingroup']
    allow_rename = True
    label = _('DHCP host')
    label_plural = _('DHCP hosts')

    takes_params = (
        Str('cn',
            cli_name='host',
            label=_('Host'),
            doc=_('Host entry name -- normally the DNS hostname, but if there is more than one entry for a host, you can add a suffix to make it unique'),
            primary_key=True,
        ),
        Str('dhcpstatements*',
            cli_name='statements',
            label=_('Statements'),
            doc=_('A DHCP configuration statement other than option'),
        ),
        Str('dhcpoption*',
            cli_name='options',
            label=_('Options'),
            doc=_('A DHCP configuration option'),
        ),
        Str('dhcpcomments?',
            cli_name='comment',
            label=_('Comment'),
            doc=_('A DHCP comment'),
        ),
        Str('dhcphwaddress?',
            cli_name='hwaddress',
            label=_('HWaddress'),
            doc=_('Hardware address, typically in form "ethernet aa:bb:cc:dd:ee:ff", 2-digit hex numbers, but we recognize all standard formats'),
            required=True,
        ),
        Str('ingroup?',
            cli_name='ingroup',
            label=_('In group'),
            doc=_('When creating a host, put it in this group'),
            flags=['virtual_attribute'],
        ),
        Str('hostname?',
            cli_name='hostname',
            label=_('Hostname'),
            doc=_('If you need to make the name of the entry something other than the hostname, use this to specify the actual hostname'),
            flags=['virtual_attribute'],
        ),
        Str('ipaddress?',
            cli_name='ipaddress',
            label=_('IPaddress'),
            doc=_('If you need to specify an IP address other than the one DNS would return, use this to specify it'),
            flags=['virtual_attribute'],
        ),

    )

    def get_dn(self, *keys, **options):
        # if it exists, using existing dn
        try:
            entry_attrs = self.backend.find_entry_by_attr('cn', keys[0], 'dhcphost', ['dn'], self.container_dn + self.api.env.basedn)
            return entry_attrs.dn
        except errors.NotFound:
            pass
        
        # otherwise we're probably creating a new one
        # if user has specified to put it in a group, do so, else default
        if options and 'ingroup' in options:
            group = options['ingroup']
            return DN(('cn', keys[0]),('cn', group)) + self.container_dn + self.api.env.basedn

        return DN(('cn', keys[0])) + self.container_dn + self.api.env.basedn

    def normalize_hwaddress(self,value):
        if value is None:
            return value
        value = value.lower()
        m = re.match('.*([-:. ]).*', value)
        if m is None:
            # if just hex digits, take it
            if (len(value) <= 12 and all(c in string.hexdigits for c in value)):
                value = value.zfill(12)
                return value[0:2]+':'+value[2:4]+':'+value[4:6]+':'+value[6:8]+':'+value[8:10]+':'+value[10:12]
            # otherwise it's not a valid format
            raise errors.ValidationError(
                name='hwaddress', error=_('missing punctuation'))
        separator = m.group(1)
        count = value.count(separator) + 1
        parts = value.split(separator)
        # this will be 12 hex digits, no separators
        nvalue = ''
        if count != len(parts):
            raise errors.ValidationError(
                name='hwaddress', error=_('inconsistent punctuation'))
        size = 0
        if count == 3:
           size = 4
        elif count == 6:
           size = 2
        else:
            raise errors.ValidationError(
                name='hwaddress', error=_('must be 3 or 6 oarts'))
        for i in range(0, count):
           nvalue = nvalue + parts[i].zfill(size)
        if not all(c in string.hexdigits for c in nvalue):
            raise errors.ValidationError(
               name='hwaddress', error=_('must be hex string'))
        return nvalue[0:2]+':'+nvalue[2:4]+':'+nvalue[4:6]+':'+nvalue[6:8]+':'+nvalue[8:10]+':'+nvalue[10:12]

@register()
class dhcphost_move(LDAPQuery):
    __doc__ = _('Move host between groups or remove from group.')

    takes_options = (
        Str('ingroup?',
            cli_name='ingroup',
            label=_('In group'),
            doc=_('Move host to this group. Omit STR to remove from group, i.e. put at top level'),
            flags=['virtual_attribute'],
        ),
    )

    has_output = output.standard_entry
    has_output_params = global_output_params

    def execute(self, *keys, **options):
        ldap = self.obj.backend

        dn = self.obj.get_dn(*keys, **options)
        assert isinstance(dn, DN)

        newdn = None
        if options and 'ingroup' in options:
            group = options['ingroup']
            if group:
                newdn = DN(('cn', keys[0]),('cn', group)) + self.obj.container_dn + self.obj.api.env.basedn
            else:
                newdn = DN(('cn', keys[0])) + self.obj.container_dn + self.obj.api.env.basedn

        else:
            raise errors.EmptyModlist()


        ldap.move_entry(dn, newdn)
        entry_attrs = ldap.get_entry(newdn)
        if group:
            entry_attrs['ingroup'] = group
        else:
            entry_attrs['ingroup'] = '--none--'
            
        entry_attrs = entry_to_dict(entry_attrs, **options)
        entry_attrs['dn'] = newdn
        
        pkey = keys[-1]

        return dict(result=entry_attrs, value=pkey_to_value(pkey, options))

    msg_summary = _('Move host "%(value)s".')

    def pre_callback(self, ldap, dn, *keys, **options):
        assert isinstance(dn, DN)
        return dn

    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        assert isinstance(dn, DN)
        return True

    def exc_callback(self, keys, options, exc, call_func, *call_args, **call_kwargs):
        raise exc


@register()
class dhcphost_mod(LDAPUpdate):
    __doc__ = _('Modify a DHCP host. Do not use for options or statements unless you want to replace all of them at once')

    msg_summary = _('Modified "%(value)s"')

    # fix up hwaddress to have ethernet prefix
    # find the DN to show. by default DN is assumed to be top level, but hosts
    #  may be in a group, so we have to do our own searcn
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        # the option is just the ethernet address, but the LDAP attr has "ethernet " prefix
        # ipaddress and hostname are represented as statement or option
        # the problem is that there could be existing values. we need to remove
        # the old value, but not disturb any others
        # to make it worse, attrs can come back as individual values or lists
        # so first normalize to a list
        if 'ipaddress' in options or 'hostname' in options:
            attrs = ldap.get_entry(dn, ['*'])
            if 'ipaddress' in options:
                # if user specified --statements, that will reset statments,
                # so start with that and ignore existing
                if 'dhcpstatements' in options:
                    statements = options['dhcpstatements']
                # otherwise start with existing
                elif 'dhcpstatements' in attrs:
                    statements = attrs['dhcpstatements']
                else:
                    statements = []
                if statements is None:
                    statements = []
                elif not isinstance(statements, (list, tuple)):
                    # seems to be indivual value; make a list of it
                    statements = [statements]
                # remove old value if any
                statements = [x for x in statements if not x.startswith('fixed-address ')]
                # now add our new value
                ip = options['ipaddress']
                if not ip is None:
                    statements.append('fixed-address ' + ip)
                # now look for ip address and add integer value as csRutgersEduDhcpIpNumber
                for st in statements:
                    if st.startswith('fixed-address'):
                        ipnumber = ipaddress.IPv4Address(st[14:].strip())
                        entry_attrs['objectClass'] = ['top', 'dhcphost', 'csRutgersEduDhcpAddresses']
                        entry_attrs['csRutgersEduDhcpIpNumber'] = int(ipnumber)
                entry_attrs['dhcpstatements'] = statements

            if 'hostname' in options:
                # if user specified --options, that will reset options,
                # so start with that and ignore existing
                if 'dhcpoption' in options:
                    doptions = options['dhcpoption']
                # otherwise start with existing
                elif 'dhcpoption' in attrs:
                    doptions = attrs['dhcpoption']
                else:
                    doptions = []
                if doptions is None:
                    doptions = []
                elif not isinstance(doptions, (list, tuple)):
                    # seems to be indivual value; make a list of it
                    doptions = [doptions]
                # remove old value if any
                doptions = [x for x in doptions if not x.startswith('host-name ')]
                # now add our new value
                host = options['hostname']
                if not host is None:
                    doptions.append('host-name "' + host + '"')
                entry_attrs['dhcpoption'] = doptions

        if 'dhcphwaddress' in options:
            entry_attrs['dhcphwaddress'] = 'ethernet ' + self.obj.normalize_hwaddress(options['dhcphwaddress'])
        return dn

@register()
class dhcphost_add_option(LDAPAddAttribute):
    __doc__ = _('Add a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('', '', entry_attrs)
        return dn

@register()
class dhcphost_remove_option(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

@register()
class dhcphost_add_statement(LDAPAddAttribute):
    __doc__ = _('Add a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('', '', entry_attrs)
        return dn

@register()
class dhcphost_remove_statement(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

@register()
class dhcphost_show(LDAPRetrieve):
    __doc__ = _('Display information about a DHCP host.')

# if this isn't at top level, it's in a group. Show the group
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if dn[1].value != 'config':
            entry_attrs['ingroup'] = dn[1].value
        return dn

@register()
class dhcphost_find(LDAPSearch):
    __doc__ = _('Find a DHCP host.')

    msg_summary = ngettext(
        '%(count)d configuration matched', '%(count)d configurations matched', 0
    )
    
# allow the user to specify searching just in a group
    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        if 'ingroup' in options:
            base_dn = DN(('cn',options['ingroup'])) + base_dn
        return (filter, base_dn, ldap.SCOPE_SUBTREE)

    # if this isn't at top level, it's in a group. show the group
    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry_attrs in entries:
            if entry_attrs.dn[1].value != 'config':
                entry_attrs['ingroup'] = entry_attrs.dn[1].value
        return truncated

@register()
class dhcphost_add(LDAPCreate):
    __doc__ = _('Add a new host. Normally this should be the DNS hostname. However if you need more than one entry for a host, you can add a number at the end to make it unique. In that case you\'ll need to add the option \'hostname "REAL HOSTNAME"\' to define the real hostname. You must include actual quotes," ", around the hostname.')


    # implement hostname and ipaddress options
    # default options for new host
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        host = str(entry_attrs['cn'])
        if 'hostname' in options:
            host = options['hostname']
            
        ip = None
        if 'ipaddress' in options:
            ip = options['ipaddress']
        else:
            try:
                ip = socket.gethostbyname(host)
            except:
                raise self.obj.handle_not_found('invalid address')

        # Statements: fixed-address 172.16.68.46
        if not ip is None:
            # have to merge with any statements in --statements
            if 'dhcpstatements' in options:
                statements = options['dhcpstatements']
                if statements is None:
                    statements = []
                else:
                    statements = list(statements)
            else:
                statements = []
            statements.append('fixed-address ' + ip)
            for st in statements:
                if st.startswith('fixed-address'):
                    ipnumber = ipaddress.IPv4Address(st[14:].strip())
                    entry_attrs['objectClass'] = ['top', 'dhcphost', 'csRutgersEduDhcpAddresses']
                    entry_attrs['csRutgersEduDhcpIpNumber'] = int(ipnumber)
            entry_attrs['dhcpstatements'] = statements

        # Options: host-name "zhu.cs.rutgers.edu"
        # if other optios are specified, merge them
        if not host is None:
            # have to merge with any options in --options
            if 'dhcpoption' in options: 
                doptions = options['dhcpoption']
                if doptions is None:
                    doptions = []
                else:
                    doptions = list(doptions)
            else:
                doptions = []
            doptions.append('host-name "' + host + '"')
            entry_attrs['dhcpoption'] = doptions

        if 'dhcphwaddress' in options:
            entry_attrs['dhcphwaddress'] = 'ethernet ' + self.obj.normalize_hwaddress(options['dhcphwaddress'])

        check_dhcp_entry(None, None, entry_addrs)

        return entry_attrs.dn

    # if this isn't at top level, it's in a group. show the group
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if dn[1].value != 'config':
            entry_attrs['ingroup'] = dn[1].value
        return dn

    msg_summary = _('Added host "%(value)s"')

@register()
class dhcphost_del(LDAPDelete):
    __doc__ = _('Delete a host.')

    msg_summary = _('Deleted host "%(value)s"')

@register()
class dhcpsubnet(LDAPObject):
    """
    DHCP object.
    NOTE: There is a separate object type for IPV6, so this is IPV4 only
    """

    container_dn = DN(('cn', 'config'), ('ou', 'dhcp'))
    object_name = _('DHCP subnet')
    object_class = ['dhcpsubnet','dhcpOptions']
    default_attributes = ['cn', 'dhcpstatements', 'dhcpoption', 'dhcpcomments','dhcpnetmask', 'dhcprange']
    allow_rename = False
    label = _('DHCP subnet')
    label_plural = _('DHCP subnets')

    def valid_ip(ugettext, value):
        try:
          if '/' in value:
              ipaddress.IPv4Network(value)
          else:
              ipaddress.IPv4Address(value)
        except ValueError:
          return _("Subnet must be a legal IP address or IP/size")

    # NOTE: the ldap schema says the addresses are separated by hyphen.
    # however the conversion code simply outputs the value, and the
    # dhcpd.conf parser expects spaces
    def valid_range(ugettext, value):
        try:
          parts = value.split(' ',1)
          if len(parts) < 1:
              return _("Range must to one or two addresses separated by space")
          ipaddress.IPv4Address(parts[0])
          if len(parts) > 1:
              ipaddress.IPv4Address(parts[0])
        except ValueError:
          return _("Range must to one or two addresses separated by space")

    def valid_mask(ugettext, value):
        try:
          mask = int(value)
          if (mask) > 30 or mask < 8:
              return _("Subnet mask must be between 8 and 30")
        except ValueError:
          return _("Subnet mask must be an integer between 8 and 30")

    takes_params = (
        Str('cn', valid_ip,
            cli_name='subnet', 
            label=_('Subnet'),
            doc=_('Subnet -- must be an IP address. CIDR length goes in the netmask option'),
            primary_key=True,
        ),
        Str('dhcpstatements*',
            cli_name='statements',
            label=_('Statements'),
            doc=_('A DHCP configuration statement other than option'),
        ),
        Str('dhcpoption*',
            cli_name='options',
            label=_('Options'),
            doc=_('A DHCP configuration option'),
        ),
        Str('dhcpcomments?',
            cli_name='comment',
            label=_('Comment'),
            doc=_('A DHCP comment'),
        ),
        Str('dhcpnetmask', valid_mask,
            cli_name='netmask',
            label=_('Netmask'),
            doc=_('Net mask, actually the CIDR bit size, i.e. a small integer'),
            required=False,
        ),
        Str('dhcprange*', valid_range,
            cli_name='range',
            label=_('Range'),
            doc=_('Range of addresses to be allocated to clients, separated by space. Can also be a single address'),
            required=False,
        ),

    )


@register()
class dhcpsubnet_mod(LDAPUpdate):
    __doc__ = _('Modify a DHCP subnet. Do not use for options or statements unless you want to replace all of them at once')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_subnetmod(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_add_option(LDAPAddAttribute):
    __doc__ = _('Add a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'
    
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_subnetmod(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_remove_option(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    # remove option should always be safe

    msg_summary = _('Modified DHCP subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_add_statement(LDAPAddAttribute):
    __doc__ = _('Add a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_subnetmod(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_remove_statement(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    # remove should always be safe

    msg_summary = _('Modified DHCP subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_show(LDAPRetrieve):
    __doc__ = _('Display information about a DHCP subnet.')

@register()
class dhcpsubnet_find(LDAPSearch):
    __doc__ = _('Find a DHCP subnet.')

    msg_summary = ngettext(
        '%(count)d subnets matched', '%(count)d subnets matched', 0
    )



@register()
class dhcpsubnet_add(LDAPCreate):
    __doc__ = _('Add a new subnet. Should be an IP subnet in CIDR format, e.g. 128.6.0.0/16. Alternatively, an IP address can be supplied with --netmask, e.g. --netmask=16.')
    
    # add in default options
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
       # convert CIDR to separate IP and mask. Validator has already checked syntax
       if '/' in keys[0]:
           sl = keys[0].split('/')
           dn = DN(('cn',sl[0])) + dn[1:]
           entry_attrs['cn'] = sl[0]
           entry_attrs['dhcpnetmask'] = sl[1]
       elif not 'dhcpnetmask' in options:
           raise errors.ValidationError(
               name=keys[0], error=_('either subnet name should include size, e.g. 128.6.0.0/16, or --netmask must be specified'))

       if not 'dhcpoption' in  entry_attrs:
          #broadcast-address 172.17.8.223, routers 172.17.8.193, subnet-mask 255.255.255.224
          cidr = entry_attrs['dhcpnetmask']
          net = None
          try: 
             net = ipaddress.IPv4Network(_(str(entry_attrs['cn']) + '/' + str(cidr)))
          except ValueError:
             raise self.obj.handle_not_found('invalid address')
          options = ['broadcast-address ' + str(net.broadcast_address),
                     'subnet-mask ' + str(net.netmask),
                     'routers ' + str(next(net.hosts()))]
          entry_attrs['dhcpoption'] = options

       # in case user did something weird, get netmask from cidr spec. that's what
       # the dhcpd ldap code does
       c = entry_attrs['dhcpnetmask']
       net = None
       try: 
           net = ipaddress.IPv4Network(_(str(entry_attrs['cn']) + '/' + str(c)))
           entry_attrs['objectClass'] = ['top', 'dhcpSubnet', 'dhcpOptions', 'csRutgersEduDhcpAddresses']
           entry_attrs['csRutgersEduDhcpIpStart'] = int(net.network_address)
           entry_attrs['csRutgersEduDhcpIpEnd'] = int(net.broadcast_address)
       except ValueError:
            raise self.obj.handle_not_found('invalid address')

       check_dhcp_entry('subnet ' + str(entry_attrs['cn']) + ' netmask ' + str(net.netmask) + '{', '}', entry_attrs);
          
       return dn
    
    msg_summary = _('Added subnets "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpsubnet_del(LDAPDelete):
    __doc__ = _('Delete a subnet.')

    msg_summary = _('Deleted subnet "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool(LDAPObject):
    """
    DHCP object.
    NOTE: there is a separate LDAP object for ipv6 pools, so this is IPv4 only
    """
    container_dn = DN(('cn', 'config'), ('ou', 'dhcp'))
    object_name = _('DHCP pool')
    object_class = ['dhcppool','dhcpOptions']
    default_attributes = ['cn', 'dhcpstatements', 'dhcpoption', 'dhcpcomments', 'dhcprange', 'dhcppermitlist']
    allow_rename = True
    label = _('DHCP pool')
    label_plural = _('DHCP pools')

    def valid_range(ugettext, value):
        try:
          parts = value.split(' ',1)
          if len(parts) < 1:
              return _("Range must to one or two addresses separated by space")
          ipaddress.IPv4Address(parts[0])
          if len(parts) > 1:
              ipaddress.IPv4Address(parts[1])
        except ValueError:
          return _("Range must to one or two addresses separated by space")

    takes_params = (
        Str('cn',
            cli_name='pool', 
            label=_('Pool'),
            doc=_('Pool -- name should look different from an IP address or a hostname'),
            primary_key=True,
        ),
        Str('dhcpstatements*',
            cli_name='statements',
            label=_('Statements'),
            doc=_('A pool configuration statement other than option'),
        ),
        Str('dhcpoption*',
            cli_name='options',
            label=_('Options'),
            doc=_('A pool configuration option'),
        ),
        Str('dhcppermitlist*',
            cli_name='permits',
            label=_('Permits'),
            doc=_('Rule starting with "permit" or "deny"'),
        ),

        Str('dhcpcomments?',
            cli_name='comment',
            label=_('Comment'),
            doc=_('A DHCP comment'),
        ),
        Str('dhcprange*', valid_range,
            cli_name='range',
            label=_('Range'),
            doc=_('Range of addresses to be allocated to clients, separated by space. Can also be a single address'),
            required=True,
        ),
        Str('insubnet?',
            cli_name='insubnet',
            label=_('In subnet'),
            doc=_('When creating a pool, put it in this subnet'),
            flags=['virtual_attribute'],
            required=True,
        ),

    )

    # in practice this only is used for create
    def get_dn(self, *keys, **options):
        # if it exists, using existing dn
        try:
            entry_attrs = self.backend.find_entry_by_attr('cn', keys[0], 'dhcppool', ['dn'], self.container_dn + self.api.env.basedn)
            return entry_attrs.dn
        except errors.NotFound:
            pass
        
        # otherwise we're probably creating a new one
        # if user has specified to put it in a subnet, do so, else default
        if options and 'insubnet' in options:
            subnet = options['insubnet']
            return DN(('cn', keys[0]),('cn', subnet)) + self.container_dn + self.api.env.basedn

        return DN(('cn', keys[0])) + self.container_dn + self.api.env.basedn


@register()
class dhcppool_mod(LDAPUpdate):
    __doc__ = _('Modify a DHCP pool. Do not use for options or statements unless you want to replace all of them at once')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_pool(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_add_option(LDAPAddAttribute):
    __doc__ = _('Add a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'
    
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_pool(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_remove_option(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_add_statement(LDAPAddAttribute):
    __doc__ = _('Add a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_pool(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_remove_statement(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_add_permit(LDAPAddAttribute):
    __doc__ = _('Add a permit/deny rule. Starts with "permit" or "deny"')
    attribute = 'dhcppermitlist'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_pool(ldap, dn, entry_attrs)

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_remove_permit(LDAPRemoveAttribute):
    __doc__ = _('Remove a permit/deny rule. Starts with "permit" or "deny"')
    attribute = 'dhcppermitlist'

    msg_summary = _('Modified DHCP pool "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_show(LDAPRetrieve):
    __doc__ = _('Display information about a DHCP pool.')

    # if this isn't at top level, it's in a subnet. Show the subnet
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if dn[1].value != 'config':
            entry_attrs['insubnet'] = dn[1].value
        return dn


@register()
class dhcppool_find(LDAPSearch):
    __doc__ = _('Find a DHCP pool.')

    # allow the user to specify searching just in a subnet
    def pre_callback(self, ldap, filter, attrs_list, base_dn, scope, *args, **options):
        if 'insubnet' in options:
            base_dn = DN(('cn',options['insubnet'])) + base_dn
        return (filter, base_dn, ldap.SCOPE_SUBTREE)


    # if it isn't at top level, it's in a subnet. show the subnet
    def post_callback(self, ldap, entries, truncated, *args, **options):
        for entry_attrs in entries:
            if entry_attrs.dn[1].value != 'config':
                entry_attrs['insubnet'] = entry_attrs.dn[1].value
        return truncated

    msg_summary = ngettext(
        '%(count)d pools matched', '%(count)d pools matched', 0
    )

@register()
class dhcppool_add(LDAPCreate):
    __doc__ = _('Add a new pool. Should be an IP pool. The CIDR size must be specified as --netmask. We strongly recommend adding options for at least broadcast-address, routers, and pool-mask (as an IP address).')
    
    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        return dhcp_pre_callback_pool(ldap, dn, entry_attrs)

    # if it isn't at top level it's in a subnet. show the subnet
    def post_callback(self, ldap, dn, entry_attrs, *keys, **options):
        if dn[1].value != 'config':
            entry_attrs['insubnet'] = dn[1].value
        return dn

    msg_summary = _('Added pools "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcppool_del(LDAPDelete):
    __doc__ = _('Delete a pool.')

    msg_summary = _('Deleted pool  "%(value)s". Once you have made all your changes to the configuration, make sure to increment the serial number, which is stored in the "comment" attribute. Otherwise the servers won\'t see the changes. Use "ipa dhcpconfig_mod config --increment""')

@register()
class dhcpgroup(LDAPObject):
    """
    DHCP object.
    """
    container_dn = DN(('cn', 'config'), ('ou', 'dhcp'))
    object_name = _('DHCP group')
    object_class = ['dhcpgroup','dhcpOptions']
    default_attributes = ['cn', 'dhcpstatements', 'dhcpoption', 'dhcpcomments']
    allow_rename = True
    label = _('DHCP group')
    label_plural = _('DHCP groups')

    takes_params = (
        Str('cn',
            cli_name='group', 
            label=_('Group'),
            doc=_('Group -- name should look different from an IP address or a hostname'),
            primary_key=True,
        ),
        Str('dhcpstatements*',
            cli_name='statements',
            label=_('Statements'),
            doc=_('A group configuration statement other than option'),
        ),
        Str('dhcpoption*',
            cli_name='options',
            label=_('Options'),
            doc=_('A group configuration option'),
        ),
        Str('dhcpcomments?',
            cli_name='comment',
            label=_('Comment'),
            doc=_('A DHCP comment'),
        ),

    )

# groups are parsed at startup, even though they are also fetched dynamically. so we need to check the group

@register()
class dhcpgroup_mod(LDAPUpdate):
    __doc__ = _('Modify a DHCP group. Do not use for options or statements unless you want to replace all of them at once')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('group {','}', entry_attrs)
        return dn

    msg_summary = _('Modified DHCP group "%(value)s".')

@register()
class dhcpgroup_add_option(LDAPAddAttribute):
    __doc__ = _('Add a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('group {','}', entry_attrs)
        return dn

    msg_summary = _('Modified DHCP group "%(value)s".')

@register()
class dhcpgroup_remove_option(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP option. Normally quoted pair: "keyword value"')
    attribute = 'dhcpoption'

    msg_summary = _('Modified DHCP group "%(value)s".')
    
@register()
class dhcpgroup_add_statement(LDAPAddAttribute):
    __doc__ = _('Add a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('group {','}', entry_attrs)
        return dn
    
    msg_summary = _('Modified DHCP group "%(value)s".')

@register()
class dhcpgroup_remove_statement(LDAPRemoveAttribute):
    __doc__ = _('Remove a DHCP statement. Normally quoted pair: "keyword value"')
    attribute = 'dhcpstatements'

    msg_summary = _('Modified DHCP group "%(value)s".')
    
@register()
class dhcpgroup_show(LDAPRetrieve):
    __doc__ = _('Display information about a DHCP group.')


@register()
class dhcpgroup_find(LDAPSearch):
    __doc__ = _('Find a DHCP group.')

    msg_summary = ngettext(
        '%(count)d groups matched', '%(count)d groups matched', 0
    )

@register()
class dhcpgroup_add(LDAPCreate):
    __doc__ = _('Add a new group. Should be an IP group. The CIDR size must be specified as --netmask. We strongly recommend adding options for at least broadcast-address, routers, and group-mask (as an IP address).')

    def pre_callback(self, ldap, dn, entry_attrs, attrs_list, *keys, **options):
        check_dhcp_entry('group {','}', entry_attrs)
        return dn
    
    msg_summary = _('Added groups "%(value)s".')

@register()
class dhcpgroup_del(LDAPDelete):
    __doc__ = _('Delete a group.')

    msg_summary = _('Deleted group  "%(value)s".')

