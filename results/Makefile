WEAK_BLOCKS := ../weak-blocks
BITCOIN_ITERATE := ../../bitcoin-iterate/bitcoin-iterate
100_BLOCKS_FILE := ../txs-352720-to-352820.csv
FULL_FILE := ../txs-352304-to-353025.csv
CORPORA := ../../bitcoin-corpus/au ../../bitcoin-corpus/sg ../../bitcoin-corpus/sf ../../bitcoin-corpus/sf-rn

all: 30-second-16-firstbonus-100-blocks.csv.xz 30-second-16-firstbonus-full.csv.xz 30-second-16-firstbonus-with-weak-full.csv.xz no-weak-100-blocks.csv.xz no-weak-full.csv.xz

30-second-16-firstbonus-100-blocks.csv.xz: $(100_BLOCKS_FILE) $(WEAK_BLOCKS)
	$(WEAK_BLOCKS) --first-bonus=16 --weak-seconds=30 $(100_BLOCKS_FILE) $(CORPORA) | xz > $@

30-second-16-firstbonus-full.csv.xz: $(FULL_FILE) $(WEAK_BLOCKS)
	$(WEAK_BLOCKS) --first-bonus=16 --weak-seconds=30 $(FULL_FILE) $(CORPORA) | xz > $@

30-second-16-firstbonus-with-weak-full.csv.xz: $(FULL_FILE) $(WEAK_BLOCKS)
	$(WEAK_BLOCKS) --include-weak --first-bonus=16 --weak-seconds=30 $(FULL_FILE) $(CORPORA) | xz > $@

no-weak-100-blocks.csv.xz:  $(100_BLOCKS_FILE) $(WEAK_BLOCKS)
	$(WEAK_BLOCKS) --no-weak $(100_BLOCKS_FILE) $(CORPORA) | xz > $@

no-weak-full.csv.xz:  $(FUKK_FILE) $(WEAK_BLOCKS)
	$(WEAK_BLOCKS) --no-weak $(FULL_FILE) $(CORPORA) | xz > $@

# Simple block analysis between peers.
%.raw: no-weak-full.csv.xz
	xzcat $< | awk '/^block,$*,/ { COUNT=5 } { if (COUNT) { print $$0; if (--COUNT == 0) exit 0; } }' > $@

%.block.txs: %.raw
	(echo BLOCK; head -n1 $< | tr ',' '\012' | tail -n +4 | sort) > $@

%.sender.txs: %.raw
	(head -n2 $< | tail -n1 | cut -d, -f2; head -n2 $< | tail -n1 | tr ',' '\012' | tail -n +3 | sort) > $@

%.info: %.sender.txs %.block.txs %.raw
	(diff -u0 $*.block.txs $*.sender.txs; echo; for base in $*.block.txs $*.sender.txs; do for l in `tail -n+3 $*.raw`; do (echo $$l | cut -d, -f2; echo $$l | tr ',' '\012' | tail -n +3 | sort) | diff -u0 $$base -; echo; done; done) | grep -v '^@' | grep -v '^[-+][-+][-+]' > $@
