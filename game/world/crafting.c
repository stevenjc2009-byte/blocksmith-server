#include "world/crafting.h"

// ── The recipe table ──────────────────────────────────────────────────────────────────
//
// Three recipes, each justified from the actual block list (world/block.h) and from what
// worldgen.c actually does today — not invented for the sake of having a table. Every
// combination that was considered and rejected is noted below so the absence reads as a
// decision, not a gap.
//
// RECIPE_DIRT_TO_GRASS (1 dirt -> 1 grass)
//   Grass blocks are placed only by worldgen (world/worldgen.c's stoneCap()/decoration
//   pass puts BLOCK_GRASS on the single top solid block of a column) and nothing in
//   worldgen.c or world/handbuilt.c makes a grass block regrow or spread at runtime — a
//   dirt block that used to be grass, or a stone-and-dirt patch dug flat for a house
//   footprint, has no way back to a grass top except mining a fresh, undisturbed column
//   somewhere else. This recipe removes exactly that friction for a builder finishing a
//   lawn or a landscaped area around a build, at a plain 1:1 rate — it re-skins material
//   the player already has, so there is no economy reason to make it lossy.
//
// RECIPE_STONE_TO_SAND (4 stone -> 1 sand)
//   Stone is the most abundant block in the game — every column has it at depth. Sand is
//   geographically confined: worldgen.c's stoneCap() ("sandy replaces the whole
//   grass-and-dirt cap with sand", line ~117) only ever places it on the columns a biome
//   check marked sandy, i.e. beaches/deserts. A player building somewhere else who wants a
//   sand accent has to either travel there or grind surplus stone for it — this recipe is
//   the second option, deliberately lossy (4:1) because it should still be worse than just
//   mining sand where it naturally occurs, or it would erase the reason sand is scarce.
//
// RECIPE_LEAVES_TO_DIRT (4 leaves -> 1 dirt)
//   Leaves are the single most disposable, most renewable material in the game: a tree's
//   whole canopy is leaves (world/worldgen.c's treePut(), the GEN_TREE_RADIUS loop), far
//   outnumbering its trunk, and worldgen.c places a new tree on essentially every forested
//   chunk it generates — there is no scarcity to protect here, unlike wood. Composting
//   surplus canopy into dirt is a physically ordinary process and gives leaves a use once
//   a build is not actively using them, in particular for a player deep in a stone-only
//   cave with no soil underfoot and no easy way back to the surface. Lossy (4:1) for the
//   same reason as the stone recipe: still worse than just digging dirt where it exists.
//
// RECIPE_COAL_ORE_TO_TORCH (1 coal ore -> 4 torches)
//   Coal ore (BLOCK_COAL_ORE, v1.8.12 "Ores") is the only fuel-shaped block in the game and
//   the torch (BLOCK_TORCH, v1.8.10 "Light") is the only light source — before this recipe
//   the torch had a full registry row, an atlas tile and working smooth lighting, but no
//   generator places one and no recipe produced one, so a player could never actually get
//   one. There are no sticks in this game and none planned (ItemId is a typedef of BlockId,
//   world/inventory.h, so a non-block item would force a type split across eleven mirrored
//   files, out of scope here), so the recipe has to be struck from coal ore alone rather
//   than from coal ore plus a shaft material the block list does not have. Four is chosen to
//   match the ratio players expect from the genre, same reasoning as RECIPE_WOOD_TO_PLANKS's
//   four. Lossless in the sense that a mined ore becomes several torches rather than being
//   destroyed for one — a torch is cheap once the ore is in hand, which is the point: light
//   should not be rarer than the ore that makes it.
//
// RECIPE_WOOD_TO_PLANKS (1 wood -> 4 planks)
//   The one recipe here that *gains* material, and the only one that should. The three
//   above are all conversions between raw blocks the world already hands out, so making
//   any of them profitable would just devalue mining; this one is a raw log becoming a
//   worked building material that worldgen never places at all, which is the ordinary
//   real relationship between a tree and a floor. Sawing one log into several boards is
//   also simply what happens, and a 1:1 recipe would read as broken.
//
//   Wood's scarcity survives it, which was the objection this file used to raise against
//   any wood recipe at all (see below): planks are an output, never an input, and there
//   is no path back from planks to wood. A player still cannot synthesize a log — they
//   can only spend one. Four is the count because a log is square in cross-section and
//   the block list has no half-blocks or stairs to spend the surplus on, so a larger
//   multiplier would just fill the inventory with a material there is little to do with
//   yet; four fills a wall fast enough to be worth the trip to a tree.
//
// What is deliberately absent:
//
//   - Wood is the input of exactly one recipe and the output of none. As an *output* it
//     would let a player synthesize the one raw material this world does not hand out on
//     every column (worldgen only places it inside a tree's trunk), which would erase the
//     scarcity that gives wood any value at all. That reasoning is unchanged and is why
//     no recipe converts anything back into BLOCK_WOOD.
//
//     This file previously argued wood should be the input of nothing either, on the
//     grounds that "nothing else in the block list is a plausible product of processing a
//     log — there is no planks or charcoal block to turn it into". That was an argument
//     about the block list, not about wood, and it stopped being true when BLOCK_PLANKS
//     was added: the missing product now exists as a real block, so the recipe is no
//     longer an item invented to justify a recipe. Charcoal is still absent and still
//     rejected on the original grounds — it would need a fuel and burning system that
//     does not exist.
//   - Sand -> stone (the reverse of RECIPE_STONE_TO_SAND) was considered — real-world
//     lithification goes that direction too — and rejected as pointless: stone is already
//     the more abundant of the two, so a recipe that turns scarce sand into abundant stone
//     has no player who would ever want it.
//   - Grass -> dirt (the reverse of RECIPE_DIRT_TO_GRASS) was considered and rejected as
//     redundant rather than wrong: dirt sits directly beneath the grass layer on every
//     column, so a player who wants dirt back from a grass block already has it one block
//     down without spending anything on a recipe.
//
// ── v1.8.15 "Furnace": 8 stone -> 1 furnace, and why this row is not optional ───────────
//
//   RECIPE_STONE_TO_FURNACE exists because without it BLOCK_FURNACE (world/block.h, id 42)
//   is UNOBTAINABLE. That is not a balance opinion, it is a reachability fact, and it was
//   found by asking where blocks enter the bag rather than by playing: there are exactly
//   three routes — invBridgeAdd() from an entity drop (main.c:5809), invBridgeAdd() from a
//   block the player broke (main.c:5893), and the crafting/withdraw path in scene/ui.c:324.
//   Worldgen places no furnace anywhere, so route two never yields one; no entity drops one,
//   so route one never does either. Route three was the only one left, and until this row
//   landed it did not carry a furnace. v1.8.15 would have shipped a version named after a
//   block, with the block registered, textured, tick-driven, save-persisted, tested by its
//   own 159-check suite — and unreachable by any player. That is the exact failure the vault
//   records as "a feature can land UNREACHABLE": every part green, the payoff absent.
//
//   8 stone is Minecraft's own cost for a furnace (eight cobblestone ringing an empty
//   centre) taken as a REFERENCE for the magnitude, not as a shape: this file has no grid to
//   arrange them in and does not want one, so it is spent here as a plain count. Eight is
//   also the largest input_count in the table by a factor of two, which is deliberate — the
//   furnace is the first crafted block that unlocks a whole system rather than converting
//   one material into another, and it should read as a project rather than a tap.
//
//   Stone is already RECIPE_STONE_TO_SAND's input at a different count, so this is the first
//   time two recipes share an input material. The header's argument for rejecting a shaped
//   grid said a grid earns its keep by disambiguating same-ingredient recipes; that argument
//   is untouched here, because these two are never ambiguous. The player picks a recipe by
//   tapping its own row in the panel — the recipe is chosen first and the ingredients spent
//   afterwards — so there is no matching step in which 8 stone and 4 stone could be confused.
//   Had ingredients been matched against a grid, this pair is exactly where a grid would have
//   become necessary; they are not, so it still is not.
//
//   Note for whoever reads the "what is deliberately absent" list above: its rejection of
//   charcoal rested on "it would need a fuel and burning system that does not exist". That
//   premise expired with this version — world/furnace.h now has both, with furnaceIsFuel()
//   and a burn clock. Charcoal is still absent, but it is now absent because nobody has
//   asked for it, NOT because the engine cannot express it. Left in place rather than
//   quietly deleted, because a rejection whose reason has expired is worth seeing.
const CraftRecipe CRAFT_RECIPES[RECIPE_COUNT] = {
	[RECIPE_DIRT_TO_GRASS] = {
		.name = "Dirt -> Grass",
		.input_item = BLOCK_DIRT, .input_count = 1,
		.output_item = BLOCK_GRASS, .output_count = 1,
	},
	[RECIPE_STONE_TO_SAND] = {
		.name = "Stone -> Sand",
		.input_item = BLOCK_STONE, .input_count = 4,
		.output_item = BLOCK_SAND, .output_count = 1,
	},
	[RECIPE_LEAVES_TO_DIRT] = {
		.name = "Leaves -> Dirt",
		.input_item = BLOCK_LEAVES, .input_count = 4,
		.output_item = BLOCK_DIRT, .output_count = 1,
	},
	[RECIPE_WOOD_TO_PLANKS] = {
		.name = "Wood -> Planks",
		.input_item = BLOCK_WOOD, .input_count = 1,
		.output_item = BLOCK_PLANKS, .output_count = 4,
	},
	[RECIPE_COAL_ORE_TO_TORCH] = {
		.name = "Coal Ore -> Torch",
		.input_item = BLOCK_COAL_ORE, .input_count = 1,
		.output_item = BLOCK_TORCH, .output_count = 4,
	},
	// Appended at the END of the enum on purpose: net/bsgame.c indexes recipes by their
	// position over the wire (bsgame.c:1332 bounds an incoming index against RECIPE_COUNT),
	// so inserting this anywhere but last would silently renumber every recipe above it and
	// leave an old client crafting the wrong thing against a new server.
	[RECIPE_STONE_TO_FURNACE] = {
		.name = "Stone -> Furnace",
		.input_item = BLOCK_STONE, .input_count = 8,
		.output_item = BLOCK_FURNACE, .output_count = 1,
	},
};

bool craftCanMake(const Inventory* inv, int recipe_index)
{
	if (!inv || recipe_index < 0 || recipe_index >= RECIPE_COUNT) return false;

	const CraftRecipe* r = &CRAFT_RECIPES[recipe_index];
	return inventoryCount(inv, r->input_item) >= r->input_count;
}

bool craftMake(Inventory* inv, int recipe_index)
{
	if (!inv || recipe_index < 0 || recipe_index >= RECIPE_COUNT) return false;
	if (!craftCanMake(inv, recipe_index)) return false;

	const CraftRecipe* r = &CRAFT_RECIPES[recipe_index];

	// Attempt the whole recipe on a scratch copy — Inventory is a small, fixed-size,
	// stack-allocated struct (no pointers inside it), so this is a plain value copy, not
	// an allocation. Nothing is written back to `inv` unless both the consume and the
	// produce steps succeed, which is what makes a refusal at either step leave `inv`
	// completely untouched without needing a hand-rolled undo.
	Inventory trial = *inv;

	const uint8_t removed = inventoryRemove(&trial, r->input_item, r->input_count);
	if (removed != r->input_count) return false;   // stale read since craftCanMake; bail, inv untouched

	uint8_t leftover = 0;
	const InvAddResult add = inventoryAdd(&trial, r->output_item, r->output_count, &leftover);
	if (add != INV_ADD_OK) return false;   // output has nowhere to go: abort, inv untouched

	*inv = trial;
	return true;
}
