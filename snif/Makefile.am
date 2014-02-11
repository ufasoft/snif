build=@build@

AM_CPPFLAGS =-Iinc -I/usr/include/libxml2 -pthread @LIBCURL_CFLAGS@
AM_CXXFLAGS =-Wno-multichar

if CLANG
AM_CXXFLAGS += -mno-sse
else
AM_CXXFLAGS += -Wno-invalid-offsetof 
endif

include am.makeinc

BUILT_SOURCES =el/ext.h.gch 

bin_PROGRAMS = icqdump

icqdump_SOURCES =					\
	$(snif_FILES)					\
	$(libext_FILES)					\
	u-config.h

dist_icqdump_SOURCES = ext_messages.h


el/ext.h.gch: el/ext.h
	$(CXXCOMPILE) -c $(CXXFLAGS) $<


el/stl/mutex : el/stl/mutex
	echo "---"

el/stl/dynamic_bitset : el/stl/dynamic_bitset
	echo "---"

el/stl/regex : el/stl/regex
	echo "---"

el/stl/thread : el/stl/thread
	echo "---"


CLEANFILES = el/ext.h.gch

