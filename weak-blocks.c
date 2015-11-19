/* FIXME: This code is very messy, including multuple traversal variants. */
#include <ccan/asort/asort.h>
#include <ccan/structeq/structeq.h>
#include <ccan/htable/htable_type.h>
#include <ccan/opt/opt.h>
#include <ccan/tal/tal.h>
#include <ccan/tal/str/str.h>
#include <ccan/tal/grab_file/grab_file.h>
#include <ccan/rbuf/rbuf.h>
#include <ccan/err/err.h>
#include <ccan/str/hex/hex.h>
#include <assert.h>
#include "../bitcoin-corpus/bitcoin-corpus.h"

#define MIN_BLOCK 352304
#define MAX_BLOCK 353025

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
static bool print_ibltdata = true;

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

static struct txinfo *add_to_block(struct block *b, const struct corpus_txid *txid)
{
	struct txinfo *txinfo;

	assert(!find_in_block(b, txid));

	txinfo = txmap_get(all_txs, txid);
	if (!txinfo)
		txinfo = unknown_txinfo(b, txid);
	txmap_add(&b->txs, txinfo);
	return txinfo;
}

static void remove_from_block(struct block *b, const struct corpus_txid *txid)
{
	if (!txmap_delkey(&b->txs, txid))
		errx(1, "Bad txid in block?");
}

struct peer {
	const char *name;
	size_t weak_blocks_sent, raw_blocks_sent, ref_blocks_sent, bytes_sent;
	size_t txs_sent;
	size_t txs_referred;
	size_t ideal_txs_unknown, ideal_txs_sent, ideal_bytes;
	struct corpus_entry *start, *end, *cur;

	/* Ring of peers. */
	struct peer *next;
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

/*
 * sf-rn and au "forget" about these transactions, received after the
 * 353014 orphan block.  My guess is that these transactions depend on
 * transactions in that 353014 orphan block: when it's orphaned, they
 * get removed (even though they're valid with the new block).
 */
static void forget_conflicts(struct peer *p, size_t blocknum)
{
	static struct corpus_txid forgotten1 = {
		{ 0x03, 0x7b, 0x4e, 0xad, 0xf6, 0x35, 0x84, 0x76,
		  0x48, 0x70, 0xbb, 0x05, 0x5a, 0x2a, 0x8e, 0x75,
		  0x51, 0x45, 0xe2, 0x7a, 0x97, 0x49, 0x0f, 0x46,
		  0xed, 0xe6, 0xdb, 0x84, 0x11, 0x14, 0xe1, 0x4e }};

	static struct corpus_txid forgotten2 = {
		{ 0x2d, 0xbb, 0x81, 0xd7, 0x3a, 0x6d, 0x9d, 0xe8,
		  0x5f, 0x2b, 0x78, 0xbc, 0xac, 0x7e, 0x35, 0x04,
		  0x07, 0xa3, 0xe7, 0x37, 0xf8, 0xd5, 0xda, 0x7e,
		  0xf1, 0xfe, 0x93, 0x38, 0x79, 0x5f, 0xb0, 0xcc } };

	static struct corpus_txid forgotten3 = {
		{ 0x98, 0x98, 0x97, 0xca, 0xc0, 0x11, 0x50, 0x01,
		  0xc7, 0x5d, 0x49, 0x13, 0xca, 0x08, 0x1b, 0x62,
		  0x63, 0xde, 0x48, 0x7d, 0x20, 0xf7, 0x0b, 0x03, 
		  0xfc, 0xfa, 0x1b, 0x46, 0x91, 0x44, 0xad, 0x39 } };

	static struct corpus_txid forgotten4 = {
		{ 0x82, 0xf5, 0x56, 0x9c, 0x49, 0x46, 0x1b, 0xbf,
		  0x1b, 0x67, 0xa1, 0xc7, 0xba, 0x09, 0xc3, 0xa0,
		  0x51, 0x29, 0x2f, 0x86, 0xa5, 0xf9, 0x7f, 0x71,
		  0x98, 0xef, 0x36, 0x44, 0x36, 0xe1, 0x6d, 0xc0 } };

	static struct corpus_txid forgotten5 = {
		{ 0x0c, 0xcd, 0x98, 0xb6, 0x94, 0x07, 0x95, 0xad,
		  0xd4, 0xbd, 0x22, 0x1e, 0xac, 0x95, 0xde, 0x8f,
		  0x8d, 0xd9, 0x2c, 0x0f, 0x2f, 0x57, 0x33, 0x03,
		  0x2d, 0x36, 0x72, 0xd5, 0x31, 0xa5, 0xd0, 0x2a } };

	static struct corpus_txid forgotten6 = {
		{ 0xa2, 0x6b, 0xa9, 0xc7, 0xeb, 0xea, 0xeb, 0xae,
		  0xb9, 0x87, 0x83, 0xc5, 0x13, 0x3e, 0x55, 0xfe,
		  0xbc, 0x75, 0xe4, 0xe2, 0x89, 0x45, 0xa8, 0x86,
		  0xc4, 0xbc, 0x1a, 0x94, 0xa7, 0xcd, 0x92, 0x60 } };

	if (blocknum == 353014) {
		/* Remove these txs iff they are in mempool. */
		txmap_delkey(&p->mempool->txs, &forgotten1);
		txmap_delkey(&p->mempool->txs, &forgotten2);
		txmap_delkey(&p->mempool->txs, &forgotten3);
		txmap_delkey(&p->mempool->txs, &forgotten4);
		txmap_delkey(&p->mempool->txs, &forgotten5);
		txmap_delkey(&p->mempool->txs, &forgotten6);
	}
}
	
// Sync up mempool based on next block.
static void next_block(struct peer *p, size_t blocknum)
{
	// Keep going until next coinbase;
	while (p->cur != p->end) {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (corpus_orphaned_coinbase(corpus_blocknum(p->cur),
						     &p->cur->txid))
				break;
			// If this fails, we hit an orphan!
			assert(corpus_blocknum(p->cur) == blocknum);
			forget_conflicts(p, corpus_blocknum(p->cur));
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
	if (corpus_maybe_orphan(blocknum - 1)) {
		forward_to_block(p, blocknum - 2);
		next_block(p, blocknum-1);
		next_block(p, blocknum);
		return;
	}

	do {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (corpus_orphaned_coinbase(corpus_blocknum(p->cur),
						     &p->cur->txid)) {
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

/* For IBLT encoding of the literal txs, we know they weren't in the
 * weak block, so we can eliminate the weak block txs from
 * consideration from both block and mempool. */
static void dump_block_without_weak(const struct block *b,
				    const struct block *weak)
{
	struct txmap_iter it;
	struct txinfo *t;
	char hexstr[hex_str_size(sizeof(t->txid))];

	for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it)) {
		if (weak && txmap_get(&weak->txs, &t->txid))
			continue;
		hex_encode(&t->txid, sizeof(t->txid), hexstr, sizeof(hexstr));
		printf(",%s", hexstr);
	}
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
			return b;
		case KNOWN:
			print_tx(p, "removing known", &p->cur->txid);
			add_to_block(b, &p->cur->txid);
			break;
		case MEMPOOL_ONLY:
			assert(find_in_block(p->mempool, &p->cur->txid));
			break;
		case UNKNOWN:
			assert(!find_in_block(p->mempool, &p->cur->txid));
			// Even best case, we'd need to send this one.
			p->ideal_bytes += add_to_block(b, &p->cur->txid)->len;
			p->ideal_txs_unknown++;
			break;
		}
		p->cur++;
	}
	errx(1, "%s: ran out of input", p->name);
}

static void skip_block(struct peer *p)
{
	p->cur++;
	while (p->cur != p->end) {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
		case INCOMING_TX:
			return;
		case KNOWN:
			/* Interestingly, txs don't seem to get returned to
			 * mempool even when we orphan block, eg sf txid
			 * e79b52d35ae3a41d5d9b5e64dee811531918f92955fde5699f8e3944d7831df */
			remove_from_block(p->mempool, &p->cur->txid);
			break;
		case MEMPOOL_ONLY:
		case UNKNOWN:
			break;
		}
		p->cur++;
	}
}

static void catchup_mempool(struct peer *p, unsigned int height)
{
	struct block *b;
	struct txmap_iter it;
	struct txinfo *t;

	while (p->cur != p->end) {
		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (corpus_orphaned_coinbase(corpus_blocknum(p->cur),
						     &p->cur->txid)) {
				skip_block(p);
				continue;
			}
			// If this fails, we hit an orphan!
			assert(corpus_blocknum(p->cur) == p->mempool->height);
			forget_conflicts(p, corpus_blocknum(p->cur));

			b = read_block_contents(p, corpus_blocknum(p->cur));
			// Now we've done encoding, remove all from our mempool
			for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it))
				txmap_delkey(&p->mempool->txs, &t->txid);
			tal_free(b);
			if (p->mempool->height == height)
				return;
			break;
		case INCOMING_TX:
			print_tx(p, "adding incoming", &p->cur->txid);
			add_to_block(p->mempool, &p->cur->txid);
			break;
		default:
			errx(1, "Unexpected entry");
		}
		p->cur++;
	}
}

static void dump_iblt_data(struct peer *peer,
			   const struct block *b,
			   const struct block *weak,
			   bool is_weak)
{
	struct peer *p;

	if (!weak) {
		/* We only dump if we're the first to find a block. */
		for (p = peer->next; p != peer; p = p->next) {
			if (p->mempool->height >= peer->mempool->height)
				return;
		}
	} else
		p = peer;

	/* height,bytes-overhead 
	 *
	 * We assume 2 bytes per tx (either a reference, or an escape). */
	printf("block,%u,%zu", b->height,
	       BLOCKHEADER_SIZE + coinbases[b->height-MIN_BLOCK]->len + sizeof(struct corpus_txid)
	       + sizeof(u16) * peer->mempool->txs.raw.elems);
	dump_block_without_weak(b, weak);
	printf("\n");

	do {
		/*
		 * Corner case: other peer hasn't even seen *previous* block.
		 * We fast-forward for this case (peer will always process
		 * blocks in order anyway).
		 */
		if (p->mempool->height + 1 < peer->mempool->height)
			catchup_mempool(p, peer->mempool->height - 1);

		printf("mempool,%s", p->name);
		dump_block_without_weak(p->mempool, weak);
		printf("\n");
		p = p->next;
	} while (p != peer);

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

static struct block *generate_weak(struct weak_blocks *weak, struct peer *peer)
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

	/* Now fill it in a weak slot. */
	for (i = 0; i < NUM_WEAK; i++) {
		if (!weak->b[i]) {
			weak->b[i] = b;
			return b;
		}
		/* We only keep one of each height. */
		if (weak->b[i]->height == b->height) {
			weak->b[i] = b;
			return b;
		}
		if (weak->b[i]->height < weak->b[min]->height)
			min = i;
	}
	/* Replace oldest. */
	weak->b[min] = b;
	return b;
}

static void encode_raw(struct peer *p, const struct block *b)
{
	struct txmap_iter it;
	struct txinfo *t;

	p->raw_blocks_sent++;
	for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it)) {
		p->txs_sent++;
		p->bytes_sent += txsize(t);
		// In the ideal case, we'd still send a 2 byte ref.
		p->ideal_bytes += 2;
		p->ideal_txs_sent++;
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
				const struct weak_blocks *weak, bool is_weak)
{
	const struct block *base = find_weak(weak, b->height);
	struct txmap_iter it;
	struct txinfo *t;

	if (print_ibltdata)
		dump_iblt_data(p, b, base, is_weak);

	/* We have to send header and coinbase. */
	p->bytes_sent += BLOCKHEADER_SIZE + coinbases[b->height-MIN_BLOCK]->len;
	p->ideal_bytes += BLOCKHEADER_SIZE + coinbases[b->height-MIN_BLOCK]->len;
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
			/* Assume we use a 2 byte escape sequence. */
			p->txs_sent++;
			p->bytes_sent += 2 + txsize(t);
		}
		// In the ideal case, we'd still send a 2 byte ref.
		p->ideal_bytes += 2;
		p->ideal_txs_sent++;
	}
}

static bool process_events(struct peer *p, unsigned int time,
			   const struct weak_blocks *weak, size_t last_block)
{
	struct block *b;
	struct txmap_iter it;
	struct txinfo *t;

	while (p->cur != p->end) {
		/* Stop at timestamp. */
		if (le32_to_cpu(p->cur->timestamp) >= time)
			return true;

		switch (corpus_entry_type(p->cur)) {
		case COINBASE:
			// If it's orphaned, ignore it.
			if (corpus_orphaned_coinbase(corpus_blocknum(p->cur),
						     &p->cur->txid)) {
				skip_block(p);
				continue;
			}
			// If this fails, we hit an orphan!
			assert(corpus_blocknum(p->cur) == p->mempool->height);
			forget_conflicts(p, corpus_blocknum(p->cur));

			// In case we reached the last block.
			if (corpus_blocknum(p->cur) == last_block)
				return false;

			b = read_block_contents(p, corpus_blocknum(p->cur));
			encode_against_weak(p, b, weak, false);
			// Now we've done encoding, remove all from our mempool
			for (t = txmap_first(&b->txs, &it); t; t = txmap_next(&b->txs, &it))
				txmap_delkey(&p->mempool->txs, &t->txid);
			tal_free(b);
			// Skip p->cur increment
			continue;
		case INCOMING_TX:
			print_tx(p, "adding incoming", &p->cur->txid);
			add_to_block(p->mempool, &p->cur->txid);
			break;
		default:
			errx(1, "%s: unexpected type %u",
			     p->name, corpus_entry_type(p->cur));
		}
		p->cur++;
	}
	errx(1, "%s: ran out of input", p->name);
}

/* Returns first block number. */
static size_t load_txmap(const char *csvfile, size_t *last_block)
{
	struct rbuf in;
	char *line;
	size_t first_block = MAX_BLOCK+1;
	*last_block = MIN_BLOCK-1;

	all_txs = tal(NULL, struct txmap);
	txmap_init(all_txs);
	if (!rbuf_open(&in, csvfile, NULL, 0))
		err(1, "Failed opening %s", csvfile);

	/* 352720,0,433a604e24c948f3eaa2af815c168b65c3f4c3e746c7b4129779cbe9a45c5d0a,102,-2516496498 */
	while ((line = rbuf_read_str(&in, '\n', realloc)) != NULL) {
		size_t blocknum;
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
		blocknum = atoi(parts[0]);
		if (t->coinbase && !corpus_orphaned_coinbase(blocknum, &t->txid)) {
			if (blocknum < MIN_BLOCK || blocknum > MAX_BLOCK)
				errx(1, "Invalid block number %zu", blocknum);
			if (coinbases[blocknum - MIN_BLOCK])
				errx(1, "Duplicate coinbase %zu", blocknum);
			coinbases[blocknum - MIN_BLOCK] = t;
			if (blocknum < first_block)
				first_block = blocknum;
			if (blocknum > *last_block)
				*last_block = blocknum;
		}
	}
	return first_block;
}

int main(int argc, char *argv[])
{
	size_t i, num_peers, first_block, last_block;
	unsigned int time, start_time, seed = 0;
	struct weak_blocks *weak;
	struct peer *peers;
	unsigned int first_bonus = 1, weak_block_seconds = 30;
	bool no_generate_weak = false;
	bool print_stats = false;
	bool include_weak = false;

	opt_register_arg("--first-bonus=<multiplier>",
			 opt_set_uintval, opt_show_uintval, &first_bonus,
			 "Difficulty adjustment for first weak block");
	opt_register_arg("--weak-seconds=<seconds>",
			 opt_set_uintval, opt_show_uintval, &weak_block_seconds,
			 "How many seconds on average for a weak block");
	opt_register_arg("--seed",
			 opt_set_uintval, NULL, &seed,
			 "Seed for number generator");
	opt_register_noarg("--stats", opt_set_bool, &print_stats,
			   "Print statistics instead of iblt data");
	opt_register_noarg("--include-weak", opt_set_bool, &include_weak,
			   "Generate results for weak as well as strong blocks");
	opt_register_noarg("--no-weak", opt_set_bool, &no_generate_weak,
			   "Don't generate weak blocks");
	opt_register_noarg("-h|--help", opt_usage_and_exit,
			   "<txids> <peer1> <peer2>...",
			   "Show this help message");
	opt_parse(&argc, argv, opt_log_stderr_exit);
	if (argc < 4)
		opt_usage_exit_fail("Need three arguments or more");
	num_peers = argc - 2;
	if (first_bonus > weak_block_seconds * num_peers)
		opt_usage_exit_fail("First bonus can't be more than %zu",
				    weak_block_seconds * num_peers);
	if (seed)
		srandom(seed);

	if (no_generate_weak)
		first_bonus = 0;

	if (print_stats)
		print_ibltdata = false;
	
	first_block = load_txmap(argv[1], &last_block);
	weak = talz(all_txs, struct weak_blocks);
	
	peers = tal_arr(weak, struct peer, num_peers);
	for (i = 0; i < num_peers; i++) {
		peers[i].name = argv[i+2];
		peers[i].start = peers[i].cur = grab_file(peers, peers[i].name);
		if (!peers[i].start)
			err(1, "Grabbing %s", peers[i].name);
		peers[i].end = peers[i].start
			+ tal_count(peers[i].start) / sizeof(*peers[i].start);
		peers[i].mempool = new_block(peers, &peers[i], first_block);
		forward_to_block(&peers[i], first_block);
		peers[i].weak_blocks_sent = peers[i].raw_blocks_sent
			= peers[i].ref_blocks_sent = peers[i].bytes_sent
			= peers[i].txs_sent = peers[i].txs_referred
			= peers[i].ideal_bytes = peers[i].ideal_txs_sent
			= peers[i].ideal_txs_unknown
			= 0;
		peers[i].next = &peers[(i + 1) % num_peers];
	}

	time = start_time = le32_to_cpu(peers[0].cur->timestamp);
	for (;;) {
		time++;
		/* Move everyone forward one second. */
		for (i = 0; i < num_peers; i++) {
			if (!process_events(&peers[i], time, weak, last_block))
				goto out;
		}
		/* Network generates a weak block ~ every 30 seconds.
		 * So each second, chance for each peer is 1 in 30*num_peers */
		for (i = 0; i < num_peers; i++) {
			long int threshold = RAND_MAX / (weak_block_seconds * num_peers);
			if (!find_weak(weak, peers[i].mempool->height))
				threshold *= first_bonus;
			if (random() < threshold) {
				struct block *wb;
				wb = generate_weak(weak, &peers[i]);
				if (include_weak)
					encode_against_weak(&peers[i], wb,
							    weak, true);
				peers[i].weak_blocks_sent++;
			}
		}
	}

out:
	if (!print_stats)
		return 0;

	printf("%lu blocks, %u seconds\n",
	       peers[0].mempool->height - first_block,
	       time - start_time);
	
	printf("Name,weak-blocks-sent,raw-blocks-sent,ref-blocks-sent,bytes-sent,txs-sent,txs-referred,ideal-txs-sent,ideal-refs-sent,ideal-bytes-sent\n");
	for (i = 0; i < num_peers; i++) {
		printf("%s,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",
		       peers[i].name,
		       peers[i].weak_blocks_sent,
		       peers[i].raw_blocks_sent,
		       peers[i].ref_blocks_sent,
		       peers[i].bytes_sent,
		       peers[i].txs_sent,
		       peers[i].txs_referred,
		       peers[i].ideal_txs_unknown,
		       peers[i].ideal_txs_sent - peers[i].ideal_txs_unknown,
		       peers[i].ideal_bytes);
	}
	return 0;
}
