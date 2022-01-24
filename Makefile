CFLAGS := -g
CXXFLAGS := -g

all: test test2 extract viruscontrol-mod.dylib

virusclient-fake.dylib: virusclient.cpp
	$(CXX) -o $@ -shared $<

viruscontrol-mod.dylib: viruscontrol.dylib virusclient-fake.dylib
	cp viruscontrol.dylib viruscontrol-mod.dylib
	install_name_tool -change \
		"/Library/Application Support/Access Music/Virus TI/Common/libVirusUSB.dylib" \
		"@executable_path/virusclient-fake.dylib" \
		viruscontrol-mod.dylib 

clean:
	rm -f viruscontrol-mod.dylib
	rm -f virusclient-fake.dylib
	rm -f test
	rm -f test2
	rm -f extract
	rm -rf *.dSYM/
