#
# Asterisk -- A telephony toolkit for Linux.
# 
# Makefile for resource modules
#
# Copyright (C) 1999-2006, Digium, Inc.
#
# This program is free software, distributed under the terms of
# the GNU General Public License
#

-include $(ASTTOPDIR)/menuselect.makeopts $(ASTTOPDIR)/menuselect.makedeps

MODULE_PREFIX=res
MENUSELECT_CATEGORY=RES
MENUSELECT_DESCRIPTION=Resource Modules

all: _all

include $(ASTTOPDIR)/Makefile.moddir_rules

ifneq ($(findstring $(OSARCH), mingw32 cygwin ),)
  # cygwin has some dependencies among res_ things.
  # We use order-only dependencies, and then add the libraries as required.
  res_agi.so: | res_speech.so
  res_agi.so_LIBS:= -lres_speech.so
endif

voice/ami.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/ami.o: voice/ami.c voice/ami.h
voice/brcm.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/brcm.o: voice/brcm.c voice/brcm.h
voice/codec.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/codec.o: voice/codec.c voice/codec.h
voice/leds.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/leds.o: voice/leds.c voice/leds.h
voice/uci.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC  -Wall -Werror
voice/uci.o: voice/uci.c voice/uci.h
voice/ucix.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/ucix.o: voice/ucix.c voice/ucix.h
voice/fw.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/fw.o: voice/fw.c voice/fw.h voice/ip.h
voice/sip.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_voice) -fPIC -Wall -Werror
voice/sip.o: voice/sip.c voice/sip.h voice/ip.h
res_voice.so: LIBS+=-lubus -lubox -ljson-c -luci
$(if $(filter res_voice,$(EMBEDDED_MODS)),modules.link,res_voice.so): voice/ami.o voice/brcm.o voice/leds.o voice/codec.o voice/ucix.o voice/uci.o voice/fw.o voice/sip.o

res_config_ldap.o: _ASTCFLAGS+=-DLDAP_DEPRECATED

ael/ael_lex.o: ael/ael_lex.c ../include/asterisk/ael_structs.h ael/ael.tab.h
ael/ael_lex.o: _ASTCFLAGS+=-I. -Iael -Wno-unused

ael/ael.tab.o: ael/ael.tab.c ael/ael.tab.h ../include/asterisk/ael_structs.h
ael/ael.tab.o: _ASTCFLAGS+=-I. -Iael -DYYENABLE_NLS=0

$(if $(filter res_ais,$(EMBEDDED_MODS)),modules.link,res_ais.so): ais/clm.o ais/evt.o
ais/clm.o ais/evt.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_ais)

$(if $(filter res_snmp,$(EMBEDDED_MODS)),modules.link,res_snmp.so): snmp/agent.o
snmp/agent.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_snmp)

$(if $(filter res_ael_share,$(EMBEDDED_MODS)),modules.link,res_ael_share.so): ael/ael_lex.o ael/ael.tab.o ael/pval.o
ael/ael_lex.o ael/ael.tab.o ael/pval.o: _ASTCFLAGS+=$(call MOD_ASTCFLAGS,res_ael_share)

ifneq ($(findstring REBUILD_PARSERS,$(MENUSELECT_CFLAGS)),)
ael/ael_lex.c: ael/ael.flex
else
ael/ael_lex.c:
endif
	$(ECHO_PREFIX) echo "   [FLEX] $< -> $@"
	$(CMD_PREFIX) (cd ael; $(FLEX) ael.flex)
	$(CMD_PREFIX) sed 's@#if __STDC_VERSION__ >= 199901L@#if !defined __STDC_VERSION__ || __STDC_VERSION__ >= 199901L@' $@ > $@.fix
	$(CMD_PREFIX) echo "#include \"asterisk.h\"" > $@
	$(CMD_PREFIX) echo >> $@
	$(CMD_PREFIX) cat $@.fix >> $@
	$(CMD_PREFIX) rm $@.fix

ifneq ($(findstring REBUILD_PARSERS,$(MENUSELECT_CFLAGS)),)
ael/ael.tab.c ael/ael.tab.h: ael/ael.y
else
ael/ael.tab.c ael/ael.tab.h:
endif
	$(ECHO_PREFIX) echo "   [BISON] $< -> $@"
	$(CMD_PREFIX) (cd ael; $(BISON) -v -d ael.y)

ael/pval.o: ael/pval.c

clean::
	rm -f snmp/*.o snmp/*.i ael/*.o ael/*.i ais/*.o ais/*.i voice/*.o voice/*.i
