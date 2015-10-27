#include <ccan/structeq/structeq.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/err/err.h>
#include <assert.h>
#include "../bitcoin-corpus/bitcoin-corpus.h"

#define MIN_BLOCK 352720
#define MAX_BLOCK 352820

struct txinfo {
	struct corpus_txid txid;
};

/* Hash txids */
static const struct corpus_txid *keyof_txinfo(const struct txinfo *t)
{
	return &t->txid;
}

static size_t hash_txid(const struct corpus_txid *txid)
{
	size_t ret;

	memcpy(&ret, txid, sizeof(ret));
	return ret;
}

static bool txid_eq(const struct txinfo *t, const struct corpus_txid *txid)
{
	return structeq(&t->txid, txid);
}

HTABLE_DEFINE_TYPE(struct txinfo, keyof_txinfo, hash_txid, txid_eq, txmap);

struct block {
	struct peer *owner;
	unsigned int height;
	/* All the non-coinbase txids. */
	struct txmap txs;
};

/* We keep weak blocks for last few blocks (sufficient here). */
#define NUM_WEAK 3
struct weak_blocks {
	struct block *b[NUM_WEAK];
};

static struct block *new_block(const tal_t *ctx, struct peer *owner,
			       size_t height)
{
	struct block *b = tal(ctx, struct block);
	b->owner = owner;
	b->height = height;
	txmap_init(&b->txs);
	return b;
}

static bool find_in_block(const struct block *block,
			  const struct corpus_txid *txid)
{
	return txmap_get(&block->txs, txid) != NULL;
}

static void add_to_block(struct block *b, const struct corpus_txid *txid)
{
	struct txinfo *txinfo = tal(b, struct txinfo);

	assert(!find_in_block(b, txid));

	txinfo->txid = *txid;
	txmap_add(&b->txs, txinfo);
}

static void remove_from_block(struct block *b, const struct corpus_txid *txid)
{
	if (!txmap_delkey(&b->txs, txid))
		errx(1, "Bad txid in block?");
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
			assert(find_in_block(p->mempool, &p->cur->txid));
			break;
		case UNKNOWN:
			assert(!find_in_block(p->mempool, &p->cur->txid));
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

static void generate_weak(struct weak_blocks *weak, struct peer *peer)
{
	/* FIXME: limit by size and fee here. */
	size_t i, min = 0;
	struct txmap_iter it;
	struct txinfo *t;
	struct block *b = new_block(weak, peer, peer->mempool->height);

	for (t = txmap_first(&peer->mempool->txs, &it);
	     t;
	     t = txmap_next(&peer->mempool->txs, &it)) {
		txmap_add(&b->txs, tal_dup(b, struct txinfo, t));
	}
	for (i = 0; i < NUM_WEAK; i++) {
		if (!weak->b[i]) {
			weak->b[i] = b;
			return;
		}
		/* We only keep one of each height. */
		if (weak->b[i]->height == b->height) {
			weak->b[i] = b;
			return;
		}
		if (weak->b[i]->height < weak->b[min]->height)
			min = i;
	}
	/* Replace oldest. */
	weak->b[min] = b;
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
			assert(find_in_block(p->mempool, &p->cur->txid));
			break;
		case UNKNOWN:
			assert(!find_in_block(p->mempool, &p->cur->txid));
			add_to_block(b, &p->cur->txid);
			break;
		}
		p->cur++;
	}
	errx(1, "%s: ran out of input", p->name);
}

/* FIXME: Implement */
static size_t txsize(const struct txinfo *t)
{
	return 254;
}

static void encode_raw(struct peer *p, const struct block *b)
{
	struct txmap_iter it;
	struct txinfo *t;

	p->raw_blocks_sent++;
	for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it)) {
		p->txs_sent++;
		p->bytes_sent += txsize(t);
	}
}

static const struct block *find_weak(const struct weak_blocks *weak,
				     unsigned int height)
{
	size_t i;

	for (i = 0; i < NUM_WEAK; i++) {
		if (weak->b[i] && weak->b[i]->height == height)
			return weak->b[i];
	}
	return NULL;
}

static void encode_against_weak(struct peer *p, const struct block *b,
				const struct weak_blocks *weak)
{
	const struct block *base = find_weak(weak, b->height);
	struct txmap_iter it;
	struct txinfo *t;

	if (!base) {
		encode_raw(p, b);
		return;
	}

	p->ref_blocks_sent++;
	/* Assume we refer to the previous block. */
	p->bytes_sent += sizeof(struct corpus_txid);

	for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it)) {
		if (find_in_block(base, &t->txid)) {
			/* 16 bits to show position. */
			p->bytes_sent += 2;
			p->txs_referred++;
		} else {
			p->txs_sent++;
			p->bytes_sent += txsize(t);
		}
	}
}

static void process_events(struct peer *p, unsigned int time,
			   const struct weak_blocks *weak)
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
			encode_against_weak(p, b, weak);
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
	struct weak_blocks *weak = talz(NULL, struct weak_blocks);
	struct peer *peers;

	if (argc < 3)
		errx(1, "Usage: %s <peer1> <peer2>...", argv[0]);

	num_peers = argc - 1;
	peers = tal_arr(weak, struct peer, num_peers);
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
				generate_weak(weak, &peers[i]);
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
