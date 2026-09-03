// Step 8.2 (data half). The recipe table and the two calls a touchscreen crafting panel
// needs: "can I make this" (for greying out a button) and "make it" (for tapping one).
//
// Pure C, no <3ds.h>, same reasoning as inventory.h.
//
// ── Shapeless, not shaped — and why there is no ingredient list either ──────────────────
//
// A shaped recipe (Minecraft's 2x2/3x3 crafting-table grid, where *where* an ingredient
// sits matters) earns its complexity by disambiguating: it lets two recipes that use the
// same ingredients in different quantities or arrangements produce different results, and
// it lets an arrangement *mean* something (an L of planks reads as a corner). Neither
// situation exists in this game's block list (world/block.h: air, grass, dirt, stone,
// sand, wood, leaves). Every recipe below is "N of exactly one raw block becomes M of
// exactly one other raw block" — there is nothing to arrange and no collision to
// disambiguate, so a positional grid would be UI and input-handling machinery bought for
// zero disambiguating power. Rejected for that reason.
//
// A shapeless recipe (an unordered bag of possibly-several ingredient types, Minecraft's
// furnace-adjacent "any arrangement, but you still need item A *and* item B") was also
// considered and also rejected, but for a different reason: nothing in the six-block list
// justifies a recipe that needs two *different* input materials — see crafting.c's
// per-recipe comments for the reasoning behind each one, and for which combinations were
// looked at and rejected as ungrounded. Because every recipe here has exactly one
// ingredient type, CraftRecipe below stores a single (item, count) input rather than a
// general list. That is not a shortcut around shapeless-vs-shaped; it is the degenerate
// case of "shapeless with a bag of one" that this content actually needs. Extending it to
// a small fixed-size ingredient array is a mechanical, low-risk change for whenever a
// future step adds a recipe that genuinely needs two materials — building that array now,
// for zero recipes that use it, is exactly the speculative generality this project's style
// rejects.
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "world/inventory.h"

typedef struct {
	const char* name;           // for the UI's recipe list label, e.g. "Dirt -> Grass"
	ItemId      input_item;
	uint8_t     input_count;
	ItemId      output_item;
	uint8_t     output_count;
} CraftRecipe;

// One entry per recipe below; see crafting.c for the table and the reasoning behind each
// row (and behind what is deliberately *not* in it — nothing produces wood).
enum {
	RECIPE_DIRT_TO_GRASS = 0,
	RECIPE_STONE_TO_SAND,
	RECIPE_LEAVES_TO_DIRT,
	RECIPE_WOOD_TO_PLANKS,
	RECIPE_COAL_ORE_TO_TORCH,
	RECIPE_STONE_TO_FURNACE,
	RECIPE_COUNT
};

extern const CraftRecipe CRAFT_RECIPES[RECIPE_COUNT];

// True if `inv` currently holds at least `CRAFT_RECIPES[recipe_index].input_count` of its
// input item. Read-only — never mutates `inv` — so the touchscreen panel can call this
// every frame to decide whether a recipe's button is enabled without any risk of it
// silently consuming anything.
bool craftCanMake(const Inventory* inv, int recipe_index);

// Attempts recipe `recipe_index` once. If the ingredient is present in sufficient quantity
// *and* the output fits in the inventory (inventoryAdd would return INV_ADD_OK), consumes
// the ingredient and adds the output, then returns true.
//
// If either condition fails — not enough ingredient, or the output has nowhere to go
// because the inventory is full — `inv` is left byte-for-byte unchanged and this returns
// false. In particular the ingredient is never consumed when the output cannot be placed:
// a craft that ate the player's last dirt and then had nowhere to put the grass block
// would be exactly the "silently eaten block" failure inventory.h's inventoryAdd is built
// to avoid, just moved one layer up, so craftMake attempts the whole recipe on a scratch
// copy of `inv` and only commits it back if every step of it actually succeeded.
bool craftMake(Inventory* inv, int recipe_index);
