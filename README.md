Weak Block Simulator for Bitcoin
================================

This is a tool which simulates nodes generating weak blocks.  It does this
using real bitcoin block data preprocessed by [bitcoin-iterate](https://github.com/rustyrussell/bitcoin-iterate), and the corresponding mempool data from [bitcoin-corpus](https://github.com/rustyrussell/bitcoin-corpus).

Interesting ranges are blocks 352720-352819 (which includes an 11-block run of mempool backlog), and the entire useful core of the corpus (352305-353009).

```bash
# Generate transaction information for blocks 352720-352819
bitcoin-iterate -q --start 352720 --end 352820 --tx %bN,%tN,%th,%tl,%tF > txs-352720-to-352820.csv
# Simulate 30-second weak blocks between peers, with first weak block 16x easier
./weak-blocks --first-bonus=16 txs-352720-to-352820.csv  ../bitcoin-corpus/au ../bitcoin-corpus/sg ../bitcoin-corpus/sf ../bitcoin-corpus/sf-rn > 30-second-weak-blocks-16-bonus.csv
```

What Are Weak Blocks
--------------------

When miners generate blocks, they inevitably generate blocks which
don't quite meet the difficulty threshold required.  We call these
*weak blocks*.

If the network were to propagate weak blocks, there are two main
advantages:

1. Everyone would have some insight into what is likely to be in the
   coming (strong) block.
2. Block transmission could be more efficient by referring to previous
   weak blocks.

The first property is interesting, but this simulator concentrates on
the second, producing an estimate for how large the (strong) blocks
would be in such a scheme.

For comparison, you can get non-weak-block output with --no-weak.

The output is designed for post-analysis, the format is as follows:

```
<FILE> := <BLOCKDESC>*
For each block, in incrementing order:
<BLOCKDESC> := <BLOCK-LINE><MEMPOOL-LINE>+
<BLOCK-LINE> := <BLOCKHEIGHT>:<OVERHEAD-BYTES>:<TXID>*
<BLOCKHEIGHT> := integer
<OVERHEAD-BYTES> := integer
<TXID> := hex // TXID
For each peer, after each <BLOCK-LINE>:
<MEMPOOL-LINE> := mempool:<PEERNAME>:<TXID>*
```

Transactions which were in previous weak blocks are eliminated from
the block TXIDs and the mempool TXIDs (though they add two bytes to
the overhead value).

Limitations of the Simulator
----------------------------

The simulator assumes each peer knows about the weak blocks instantly,
thus there is no problem with referring to a weak block they haven't
seen yet.

It assumes a simple 16-bit encoding to calculate the overhead bytes.

The block range is currently hard coded to cover the point in
bitcoin-corpus where blocks filled.

Parameters to the Simulator
---------------------------

You can control how often weak blocks occur on average (default: 30
seconds), and also how much bonus the first weak block gets (default:
1, which means no bonus).  The bonus is useful when transactions are
backlogged, as a full block can be mined almost instantly (when there
won't be a weak block to help encode it).

You can also adjust the seed for the random number generator, which
can have dramatic effect: I recommend multiple runs with different
seeds for statistical analysis.
