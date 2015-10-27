#include <ccan/structeq/structeq.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/err/err.h>
#include <assert.h>
#include "../bitcoin-corpus/bitcoin-corpus.h"

#define MIN_BLOCK 352720
#define MAX_BLOCK 352820

struct block {
	struct peer *owner;
	unsigned int height;
	/* All the non-coinbase txids. */
	struct corpus_txid *txids;
};

static struct block *new_block(const tal_t *ctx, struct peer *owner,
			       size_t height)
{
	struct block *b = tal(ctx, struct block);
	b->owner = owner;
	b->height = height;
	b->txids = tal_arr(b, struct corpus_txid, 0);
	return b;
}

/* Inefficient, but simple. */
static int find_in_block(const struct block *block,
			 const struct corpus_txid *txid)
{
	size_t i;

	for (i = 0; i < tal_count(block->txids); i++)
		if (structeq(&block->txids[i], txid))
			return i;
	return -1;
}

static void add_to_block(struct block *b, const struct corpus_txid *txid)
{
	size_t n = tal_count(b->txids);
	assert(find_in_block(b, txid) == -1);

	tal_resize(&b->txids, n+1);
	b->txids[n] = *txid;
}

static void remove_from_block(struct block *b, const struct corpus_txid *txid)
{
	int n = find_in_block(b, txid);
	if (n == -1)
		errx(1, "Bad txid in block?");
	memmove(b->txids + n, b->txids + n + 1,
		(tal_count(b->txids) - n - 1) * sizeof(*b->txids));
	tal_resize(&b->txids, tal_count(b->txids)-1);
}

struct peer {
	const char *name;
	/* FIXME: bytes_sent doesn't include weak blocks! */
	size_t weak_blocks_sent, raw_blocks_sent, ref_blocks_sent, bytes_sent;
	size_t txs_sent;
	size_t txs_referred;
	struct corpus_entry *start, *end, *cur;

	struct block *mempool;
};

static void print_tx(struct peer *p,
		     const char *desc, const struct corpus_txid *txid)
{
#ifdef DEBUG
	char hexstr[hex_str_size(sizeof(*txid))];
	hex_encode(txid, sizeof(*txid), hexstr, sizeof(hexstr));
	printf("%s: %s %s\n", p->name, desc, hexstr);
#endif
}

// We identify orphaned blocks by coinbase.
static bool orphaned(const struct corpus_txid *txid)
{
	static struct corpus_txid orphan_352802
		= { { 0x79, 0xb1, 0xc3, 0x09, 0xab, 0x8a, 0xb9, 0x2b,
		      0xca, 0x4d, 0x07, 0x50, 0x8e, 0x0f, 0x59, 0x6f,
		      0x87, 0x2f, 0x66, 0xc6, 0xdb, 0x4d, 0x36, 0x67,
		      0x13, 0x3a, 0x37, 0x17, 0x20, 0x55, 0xe9, 0x7b } };

	return structeq(&orphan_352802, txid);
}

static bool maybe_orphan(size_t blocknum)
{
	return blocknum == 352802;
}

// Sync up mempool based on next block.
static void next_block(struct peer *p, size_t blocknum)
{
	// Keep going until next coinbase;
	while (p->cur != p->end) {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (orphaned(&p->cur->txid))
				break;
			// If this fails, we hit an orphan!
			assert(corpus_blocknum(p->cur) == blocknum);
			return;
		case INCOMING_TX:
			add_to_block(p->mempool, &p->cur->txid);
			print_tx(p, "adding", &p->cur->txid);
			break;
		case KNOWN:
			// It was in block, so remove from mempool.
			remove_from_block(p->mempool, &p->cur->txid);
			print_tx(p, "removing", &p->cur->txid);
			break;
		case MEMPOOL_ONLY:
			assert(find_in_block(p->mempool, &p->cur->txid) >= 0);
			break;
		case UNKNOWN:
			assert(find_in_block(p->mempool, &p->cur->txid) < 0);
			break;
		}
		p->cur++;
	}
	errx(1, "No block %zu for peer %s", blocknum, p->name);
}

// We sync the mempool at the block before.
static void forward_to_block(struct peer *p, size_t blocknum)
{
	bool prev_block = false;

	// Corner case: previous blocknum is orphan.  Re-use next_block logic().
	if (maybe_orphan(blocknum - 1)) {
		forward_to_block(p, blocknum - 2);
		next_block(p, blocknum-1);
		next_block(p, blocknum);
		return;
	}

	do {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (orphaned(&p->cur->txid)) {
				break;
			}
			if (corpus_blocknum(p->cur) == blocknum) {
				assert(prev_block);
				return;
			}
			assert(!prev_block);
			prev_block = (corpus_blocknum(p->cur) == blocknum - 1);
			break;
		case INCOMING_TX:
		case MEMPOOL_ONLY:
			if (prev_block) {
				// Add this to the mempool.
				print_tx(p, "init adding", &p->cur->txid);
				add_to_block(p->mempool, &p->cur->txid);
			}
			break;
		case KNOWN:
		case UNKNOWN:
			break;
		}
		p->cur++;
	} while (p->cur != p->end);
	errx(1, "No block number %zu for peer %s", blocknum, p->name);
}

static struct block *generate_weak(const tal_t *ctx, struct peer *peer)
{
	/* FIXME: limit by size and fee here. */
	struct block *b = new_block(ctx, peer, peer->mempool->height);

	b->txids = tal_dup_arr(b, struct corpus_txid, peer->mempool->txids,
			       tal_count(peer->mempool->txids), 0);
	return b;
}

static struct block *read_block_contents(struct peer *p, size_t block_height)
{
	struct block *b = new_block(NULL, p, block_height);

	p->cur++;
	while (p->cur != p->end) {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
		case INCOMING_TX:
			p->mempool->height++;
			/* Caller increments, so decrement here! */
			p->cur--;
			return b;
		case KNOWN:
			print_tx(p, "removing known", &p->cur->txid);
			remove_from_block(p->mempool, &p->cur->txid);
			add_to_block(b, &p->cur->txid);
			break;
		case MEMPOOL_ONLY:
			assert(find_in_block(p->mempool, &p->cur->txid) >= 0);
			break;
		case UNKNOWN:
			assert(find_in_block(p->mempool, &p->cur->txid) < 0);
			add_to_block(b, &p->cur->txid);
			break;
		}
		p->cur++;
	}
	errx(1, "%s: ran out of input", p->name);
}

/* FIXME: Implement */
static size_t txsize(const struct corpus_txid *txid)
{
	return 254;
}

static void encode_raw(struct peer *p, const struct block *b)
{
	size_t i, n = tal_count(b->txids);

	p->raw_blocks_sent++;
	for (i = 0; i < n; i++) {
		p->txs_sent++;
		p->bytes_sent += txsize(&b->txids[i]);
	}
}

static void encode_against_weak(struct peer *p, const struct block *b,
				const struct block *weak)
{
	size_t i, n = tal_count(b->txids);

	p->ref_blocks_sent++;
	/* Assume we refer to the previous block. */
	p->bytes_sent += sizeof(struct corpus_txid);
	for (i = 0; i < n; i++) {
		if (find_in_block(weak, &b->txids[i]) >= 0) {
			/* 16 bits to show position. */
			p->bytes_sent += 2;
			p->txs_referred++;
		} else {
			p->txs_sent++;
			p->bytes_sent += txsize(&b->txids[i]);
		}
	}
}

static void process_events(struct peer *p, unsigned int time,
			   const struct block *weak)
{
	struct block *b;

	while (p->cur != p->end) {
		/* Stop at timestamp. */
		if (le32_to_cpu(p->cur->timestamp) >= time)
			return;

		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (orphaned(&p->cur->txid))
				break;
			// If this fails, we hit an orphan!
			assert(corpus_blocknum(p->cur) == p->mempool->height);

			b = read_block_contents(p, corpus_blocknum(p->cur));
			if (weak && weak->height == b->height)
				encode_against_weak(p, b, weak);
			else {
				printf("%s: can't encode %u: weak %s height %u\n",
				       p->name, b->height,
				       weak ? weak->owner->name : "",
				       weak ? weak->height : 0);
				encode_raw(p, b);
			}
			tal_free(b);
			break;
		case INCOMING_TX:
			print_tx(p, "adding incoming", &p->cur->txid);
			add_to_block(p->mempool, &p->cur->txid);
			break;
		/* Can happen if we're skipping an orphan! */
		case KNOWN:
			remove_from_block(p->mempool, &p->cur->txid);
			break;
		default:
			break;
		}
		p->cur++;
	}
	errx(1, "%s: ran out of input", p->name);
}

int main(int argc, char *argv[])
{
	size_t i, num_peers;
	unsigned int time, start_time;
	struct block *weak = NULL;
	struct peer *peers;

	if (argc < 3)
		errx(1, "Usage: %s <peer1> <peer2>...", argv[0]);

	num_peers = argc - 1;
	peers = tal_arr(NULL, struct peer, num_peers);
	for (i = 0; i < num_peers; i++) {
		peers[i].name = argv[i+1];
		peers[i].start = peers[i].cur = grab_file(peers, argv[i+1]);
		if (!peers[i].start)
			err(1, "Grabbing %s", argv[i+1]);
		peers[i].end = peers[i].start
			+ tal_count(peers[i].start) / sizeof(*peers[i].start);
		peers[i].mempool = new_block(peers, &peers[i], MIN_BLOCK);
		forward_to_block(&peers[i], MIN_BLOCK);
		peers[i].weak_blocks_sent = peers[i].raw_blocks_sent
			= peers[i].ref_blocks_sent = peers[i].bytes_sent
			= peers[i].txs_sent = peers[i].txs_referred
			= 0;
	}

	time = start_time = le32_to_cpu(peers[0].cur->timestamp);
	while (peers[0].mempool->height < MAX_BLOCK) {
		time++;
		/* Move everyone forward one second. */
		for (i = 0; i < num_peers; i++)
			process_events(&peers[i], time, weak);
		/* Network generates a weak block ~ every 30 seconds.
		 * So each second, chance for each peer is 1 in 30*num_peers */
		for (i = 0; i < num_peers; i++) {
			if (random() < RAND_MAX / (30 * num_peers)) {
				weak = generate_weak(peers, &peers[i]);
				peers[i].weak_blocks_sent++;
			}
		}
	}
	printf("%u blocks, %u seconds\n", peers[0].mempool->height - MIN_BLOCK,
	       time - start_time);
	
	printf("Name,weak-blocks-sent,raw-blocks-sent,ref-blocks-sent,bytes-sent,txs-sent,txs-referred\n");
	for (i = 0; i < num_peers; i++) {
		printf("%s,%zu,%zu,%zu,%zu,%zu,%zu\n",
		       peers[i].name,
		       peers[i].weak_blocks_sent,
		       peers[i].raw_blocks_sent,
		       peers[i].ref_blocks_sent,
		       peers[i].bytes_sent,
		       peers[i].txs_sent,
		       peers[i].txs_referred);
	}
	return 0;
}
