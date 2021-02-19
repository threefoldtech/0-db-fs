all release production:
	$(MAKE) -C src $@
	cp -f src/zdbfs zdbfs

clean:
	$(MAKE) -C src $@

mrproper: clean
	rm -f zdbfs
