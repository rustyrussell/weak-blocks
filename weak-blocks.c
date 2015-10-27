#include <ccan/asort/asort.h>
#include <ccan/structeq/structeq.h>
#include <ccan/htable/htable_type.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <assert.h>
#include "../bitcoin-corpus/bitcoin-corpus.h"

#define MIN_BLOCK 352720
#define MAX_BLOCK 352820

#define BLOCKHEADER_SIZE 80
#define BLOCKSIZE 1000000

struct txinfo {
	struct corpus_txid txid;
	bool coinbase;
	unsigned int fee;
	unsigned int len;
};

/* Map of all the txs. */
static struct txmap *all_txs;
static struct txinfo *coinbases[MAX_BLOCK + 1 - MIN_BLOCK];

/* If we don't know about tx, use approximations. */
static struct txinfo *unknown_txinfo(const tal_t *ctx,
				     const struct corpus_txid *txid)
{
	struct txinfo *txinfo = tal(ctx, struct txinfo);

	txinfo->txid = *txid;
	txinfo->coinbase = false;
	txinfo->fee = 10000;
	txinfo->len = 254;

	return txinfo;
}

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

static size_t txsize(const struct txinfo *t)
{
	return t->len;
}

static double txfee_per_byte(const struct txinfo *t)
{
	return (double)t->fee / t->len;
}

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
	struct txinfo *txinfo;

	assert(!find_in_block(b, txid));

	txinfo = txmap_get(all_txs, txid);
	if (!txinfo)
		txinfo = unknown_txinfo(b, txid);
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

static int cmp_feerate(struct txinfo *const *a, struct txinfo *const *b,
		       void *unused)
{
	double fratea = txfee_per_byte(*a), frateb = txfee_per_byte(*b);

	if (fratea > frateb)
		return 1;
	else if (frateb > fratea)
		return -1;
	return 0;
}

static void generate_weak(struct weak_blocks *weak, struct peer *peer)
{
	struct txinfo **sorted;
	size_t i, total, max, min = 0;
	struct txmap_iter it;
	struct txinfo *t;
	struct block *b;

	sorted = tal_arr(weak, struct txinfo *, peer->mempool->txs.raw.elems);
	for (i = 0, t = txmap_first(&peer->mempool->txs, &it);
	     t;
	     t = txmap_next(&peer->mempool->txs, &it)) {
		sorted[i++] = t;
	}
	assert(i == peer->mempool->txs.raw.elems);

	asort(sorted, i, cmp_feerate, NULL);

	b = new_block(weak, peer, peer->mempool->height);
	max = BLOCKSIZE - BLOCKHEADER_SIZE;

	/* We do first fill for blocks. */
	total = coinbases[b->height-MIN_BLOCK]->len;
	for (i = 0; i < peer->mempool->txs.raw.elems; i++) {
		if (total + sorted[i]->len > max)
			break;
		txmap_add(&b->txs, sorted[i]);
		total += sorted[i]->len;
	}
	printf("Block size %u is %zu (%zu/%zu)\n", b->height, total,
	       i, peer->mempool->txs.raw.elems);

	/* Now fill it in a weak slot. */
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

static void load_txmap(const char *csvfile)
{
	struct rbuf in;
	char *line;

	all_txs = tal(NULL, struct txmap);
	txmap_init(all_txs);
	if (!rbuf_open(&in, csvfile, NULL, 0))
		err(1, "Failed opening %s", csvfile);

	/* 352720,0,433a604e24c948f3eaa2af815c168b65c3f4c3e746c7b4129779cbe9a45c5d0a,102,-2516496498 */
	while ((line = rbuf_read_str(&in, '\n', realloc)) != NULL) {
		struct txinfo *t = tal(all_txs, struct txinfo);
		char **parts = tal_strsplit(NULL, line, ",", STR_EMPTY_OK);
		if (tal_count(parts) != 6)
			errx(1, "Invalid line in %s: '%s'", csvfile, line);
		t->coinbase = streq(parts[1], "0");
		if (!hex_decode(parts[2], strlen(parts[2]), t->txid.id,
				sizeof(t->txid.id)))
			errx(1, "Invalid txid in %s: '%s'", csvfile, parts[2]);
		t->len = atoi(parts[3]);
		if (!t->len)
			errx(1, "Invalid len in %s: '%s'", csvfile, parts[3]);
		t->fee = atoi(parts[4]);
		txmap_add(all_txs, t);
		if (t->coinbase && !orphaned(&t->txid)) {
			size_t blocknum = atoi(parts[0]);

			if (blocknum < MIN_BLOCK || blocknum > MAX_BLOCK)
				errx(1, "Invalid block number %zu", blocknum);
			if (coinbases[blocknum - MIN_BLOCK])
				errx(1, "Duplicate coinbase %zu", blocknum);
			coinbases[blocknum - MIN_BLOCK] = t;
		}
	}
}

int main(int argc, char *argv[])
{
	size_t i, num_peers;
	unsigned int time, start_time;
	struct weak_blocks *weak;
	struct peer *peers;

	if (argc < 4)
		errx(1, "Usage: %s <txids> <peer1> <peer2>...", argv[0]);

	load_txmap(argv[1]);
	weak = talz(all_txs, struct weak_blocks);
	
	num_peers = argc - 2;
	peers = tal_arr(weak, struct peer, num_peers);
	for (i = 0; i < num_peers; i++) {
		peers[i].name = argv[i+2];
		peers[i].start = peers[i].cur = grab_file(peers, peers[i].name);
		if (!peers[i].start)
			err(1, "Grabbing %s", peers[i].name);
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
