"""DESIGN §9 group 1: policy tiers, normalization and bypass attempts."""
from __future__ import annotations

import pytest

from minecraft_rcon_mcp.policy import (
    HARD_CONFIRM,
    HARD_DENY,
    INDIRECT_MARKERS,
    MAX_COMMAND_BYTES,
    MESSAGE_ROOTS,
    CommandRejected,
    Decision,
    Policy,
    Tier,
    classify,
    load_default_policy,
    merge_policy,
    normalize,
)

RW = "read-write"
RO = "read-only"
POLICY = load_default_policy()


def tier_of(command, policy=POLICY, mode=RW) -> Tier:
    return classify(command, mode, policy).tier


# ------------------------------------------------------------------------------------------ default families

READ_EXAMPLES = [
    "list",
    "list uuids",
    "tick query",
    "time query daytime",
    "data get entity Bot1 Pos",
    "data get block 0 64 0",
    "seed",
    "difficulty",
    "gamerule doDaylightCycle",
    "scoreboard objectives list",
    "scoreboard players list Bot1",
    "scoreboard players list @a",  # read tier never escalates on selectors
    "team list red",
    "worldborder get",
    "forceload query 0 0",
    "locate structure minecraft:village_plains",
    "datapack list enabled",
    "version",
    "help tp",
    "help",  # bare query forms
    "datapack list",
    "forceload query",
    "spark health",
    "spark tps",
    "tps",
    "LIST",  # root is matched case-insensitively
]

WRITE_EXAMPLES = [
    "say hello",
    'tellraw Bot1 {"text":"hi"}',
    "title Bot1 title hi",
    "tp Bot1 0 64 0",
    "teleport Bot1 0 64 0",
    "give Bot1 minecraft:stone 64",
    "clear Bot1",
    "effect give Bot1 minecraft:speed",
    "summon minecraft:zombie 0 64 0",
    "setblock 0 64 0 minecraft:stone",
    "time set day",
    "weather clear",
    "gamerule doDaylightCycle false",
    "gamemode creative Bot1",
    "forceload add 0 0",
    "forceload remove 0 0",
    "scoreboard objectives add kills playerKillCount",
    "scoreboard players set Bot1 kills 3",
    "team add red",
    "tag Bot1 add tester",
    "attribute Bot1 minecraft:generic.max_health base set 40",
    "damage Bot1 5",
    "xp add Bot1 10",
    "experience add Bot1 10",
    "spawnpoint Bot1 0 64 0",
    "playsound minecraft:block.note_block.harp master Bot1",
    "particle minecraft:flame 0 64 0",
    "save-all",
    "save-on",
    "player Bot1 spawn at 0 64 0",
    "data merge entity Bot1 {Invulnerable:1b}",
    "data modify entity Bot1 Health set value 20f",
    "data remove entity Bot1 Tags",
]

CONFIRM_EXAMPLES = [
    "stop",
    "op Steve",
    "deop Steve",
    "ban Steve",
    "ban-ip 1.2.3.4",
    "pardon Steve",
    "pardon-ip 1.2.3.4",
    "whitelist off",
    "kick Steve",
    "kill @e",
    "kill @e[type=zombie,limit=1]",  # kill is HARD_CONFIRM whatever the selector
    "kill Bot1",
    "fill 0 0 0 10 10 10 minecraft:air",
    "clone 0 0 0 1 1 1 5 5 5",
    "save-off",
    "reload",
    "lp user Steve permission set *",
    "luckperms user Steve parent add admin",
    "perm add Steve all",
    "difficulty hard",
    "defaultgamemode creative",
    "worldborder set 100",
    "worldborder center 0 0",
    "datapack enable file/x",
    "datapack disable file/x",
    "spreadplayers 0 0 10 100 false Bot1",
    "function mypack:wipe",
    "schedule function mypack:wipe 10t",
    "setworldspawn 0 64 0",
    "tick freeze",  # every tick form but the exact "tick query" can stall the server
    "tick rate 40",
    "tick query extra",
    "gamerule a b c",  # neither the query nor the set form
    "list extra",
    "unknowncommand",
    "/set stone",  # after normalize: "//set stone" → root "/set"
]

DENY_EXAMPLES = [
    "debug start",
    "debug",
    "perf start",
    "jfr start",
    "publish",
    "publish true survival 25566",
    "transfer example.com 25565 Steve",
]


@pytest.mark.parametrize("command", READ_EXAMPLES)
def test_read_family(command):
    for mode in (RW, RO):
        decision = classify(command, mode, POLICY)
        assert decision.tier is Tier.READ, decision
        assert decision.allowed and not decision.needs_confirmation


@pytest.mark.parametrize("command", WRITE_EXAMPLES)
def test_write_family(command):
    decision = classify(command, RW, POLICY)
    assert decision.tier is Tier.WRITE, decision
    assert decision.allowed and not decision.needs_confirmation


@pytest.mark.parametrize("command", CONFIRM_EXAMPLES)
def test_confirm_family(command):
    decision = classify(command, RW, POLICY)
    assert decision.tier is Tier.CONFIRM, decision
    assert not decision.allowed and decision.needs_confirmation


@pytest.mark.parametrize("command", DENY_EXAMPLES)
@pytest.mark.parametrize("mode", [RW, RO])
def test_deny_family_refused_in_both_modes(command, mode):
    decision = classify(command, mode, POLICY)
    assert decision.tier is Tier.DENY
    assert not decision.allowed and not decision.needs_confirmation


# ------------------------------------------------------------------------------------------ modes


@pytest.mark.parametrize("command", WRITE_EXAMPLES[:5] + CONFIRM_EXAMPLES[:5] + ["unknowncommand"])
def test_read_only_refuses_write_and_confirm(command):
    decision = classify(command, RO, POLICY)
    assert decision.tier in (Tier.WRITE, Tier.CONFIRM)
    assert not decision.allowed and not decision.needs_confirmation
    assert "read-only" in decision.reason


def test_unknown_command_confirm_on_rw_refused_on_ro():
    rw = classify("frobnicate now", RW, POLICY)
    ro = classify("frobnicate now", RO, POLICY)
    assert rw.tier is Tier.CONFIRM and rw.needs_confirmation and not rw.allowed
    assert ro.tier is Tier.CONFIRM and not ro.needs_confirmation and not ro.allowed


@pytest.mark.parametrize("mode", ["", "readwrite", "READ-WRITE", "admin", None])
def test_unknown_mode_behaves_as_read_only(mode):
    assert classify("say hi", mode, POLICY).allowed is False
    assert classify("stop", mode, POLICY).needs_confirmation is False
    assert classify("list", mode, POLICY).allowed is True


def test_decision_shape():
    decision = classify("/list", RW, POLICY)
    assert isinstance(decision, Decision)
    assert decision.normalized == "list"
    assert isinstance(decision.reason, str) and decision.reason


# ------------------------------------------------------------------------------------------ normalization


@pytest.mark.parametrize(
    "raw, expected",
    [
        ("/list", "list"),
        ("list", "list"),
        ("  list  ", "list"),
        ("say   hello    world", "say hello world"),
        ("  /say  Hello  ", "say Hello"),
        ("/Say Hello World", "Say Hello World"),  # original casing is kept for sending
        ("//set stone", "/set stone"),  # only ONE slash is stripped
        ("/ stop", "stop"),
        ("tp  Bot1   0 64 0", "tp Bot1 0 64 0"),
    ],
)
def test_normalize(raw, expected):
    assert normalize(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "/",
        "/   ",
        "say hi\nstop",
        "say hi\r\nstop",
        "say hi\rstop",
        "say hi\x00",
        "\tstop",
        "stop\t",
        "say\thi",
        "say \x1b[31mred",
        "say \x7f",
        "say \x85",  # C1 next-line
        "say hi stop",  # line separator
        "say hi stop",  # paragraph separator
        "say ‮stop",  # right-to-left override: could disguise the command shown to a human
        "s​top",  # zero-width space
        "say " + "a" * (MAX_COMMAND_BYTES - 3),  # 1401 bytes
        "say " + "é" * 699,  # 1402 bytes, 703 characters
    ],
)
def test_normalize_rejects(raw):
    with pytest.raises(CommandRejected):
        normalize(raw)
    decision = classify(raw, RW, POLICY)
    assert decision.tier is Tier.DENY
    assert decision.normalized == ""
    assert not decision.allowed and not decision.needs_confirmation


def test_length_limit_is_in_utf8_bytes():
    ok = "say " + "a" * (MAX_COMMAND_BYTES - 4)
    assert len(ok.encode()) == MAX_COMMAND_BYTES
    assert normalize(ok) == ok
    ok_multibyte = "say " + "é" * 698
    assert len(ok_multibyte.encode()) == 1400
    assert classify(ok_multibyte, RW, POLICY).tier is Tier.WRITE


@pytest.mark.parametrize("junk", [None, 123, b"stop", ["stop"], object()])
def test_classify_never_raises_on_non_strings(junk):
    decision = classify(junk, RW, POLICY)
    assert decision.tier is Tier.DENY and decision.normalized == ""


def test_classify_never_raises_on_broken_policy():
    broken = Policy(read=("* list",))  # wildcard root is invalid
    decision = classify("list", RW, broken)
    assert decision.tier is Tier.DENY and not decision.allowed


# ------------------------------------------------------------------------------------------ bypass attempts


@pytest.mark.parametrize(
    "command",
    ["stop", "STOP", "Stop", "sToP", "/Stop", "/STOP", "  stop  ", "   /stop", "stop   ", "/stop now"],
)
def test_stop_spellings_all_need_confirmation(command):
    decision = classify(command, RW, POLICY)
    assert decision.tier is Tier.CONFIRM and decision.needs_confirmation
    assert decision.normalized.lower().startswith("stop")
    assert classify(command, RO, POLICY).allowed is False


@pytest.mark.parametrize(
    "command, tier",
    [
        ("execute as @a run stop", Tier.CONFIRM),
        ("execute as @a run op Steve", Tier.CONFIRM),
        ("execute as @a run debug start", Tier.DENY),
        ("execute as @a at @s run execute as @s run kill @e", Tier.CONFIRM),
        ("execute run execute run kill @e", Tier.CONFIRM),
        ("execute if entity @e", Tier.READ),  # no run, no store: only a test
        ("execute if entity @e[type=zombie] run list", Tier.READ),
        ("execute as runner run list", Tier.READ),  # "runner" is not "run"
        ("execute as @s run say I will run", Tier.WRITE),
        ("EXECUTE as @s RUN stop", Tier.CONFIRM),  # "RUN" is treated as run
        ("execute as @s run", Tier.CONFIRM),  # nothing after run
        ("execute positioned 0 64 0 run tp Bot1 ~ ~ ~", Tier.WRITE),
        ("execute as Bot1 run gamerule doDaylightCycle", Tier.READ),
        ("return run list", Tier.READ),
        ("return run debug start", Tier.DENY),
        ("return run stop", Tier.CONFIRM),
        ("return 1", Tier.CONFIRM),  # not a wrapper: unknown command
    ],
)
def test_execute_classifies_the_inner_command(command, tier):
    assert tier_of(command) is tier


@pytest.mark.parametrize(
    "command, tier",
    [
        # a player or score holder literally named "run": every standalone run is a possible split point
        ("execute as run run debug start", Tier.DENY),
        ("execute if score run obj matches 1 run stop", Tier.CONFIRM),
        ("execute as run run list", Tier.CONFIRM),  # "run list" itself is an unknown command
        ("execute as @s run say run stop", Tier.CONFIRM),  # conservative: "stop" is a possible remainder
    ],
)
def test_execute_every_run_token_is_a_possible_split(command, tier):
    assert tier_of(command) is tier


@pytest.mark.parametrize(
    "command, tier",
    [
        # DESIGN: "the remainder after run decides"; we also keep the side effect of the prefix (stricter)
        ("execute store result score x y run data get entity @s Health", Tier.WRITE),
        ("execute store result entity @s Health float 1 run data get entity Bot1 Health", Tier.WRITE),
        ("execute store result score x y", Tier.WRITE),  # no run: write because of store
        ("execute summon minecraft:zombie", Tier.WRITE),
        ("execute summon minecraft:zombie run list", Tier.WRITE),
        ("execute if function mypack:wipe", Tier.CONFIRM),  # 'execute if function' runs a function
        ("execute if function mypack:wipe run list", Tier.CONFIRM),
        ("execute store result score x y run stop", Tier.CONFIRM),  # the inner tier still wins when higher
    ],
)
def test_execute_prefix_side_effects(command, tier):
    assert tier_of(command) is tier


def test_execute_nesting_depth_8_allowed_9_denied():
    eight = "execute run " * 8 + "list"
    nine = "execute run " * 9 + "list"
    assert tier_of(eight) is Tier.READ
    assert tier_of(nine) is Tier.DENY
    assert tier_of("execute as @s run " * 8 + "say hi") is Tier.WRITE
    assert tier_of("execute as @s run " * 9 + "say hi") is Tier.DENY
    assert tier_of("return run " * 9 + "list") is Tier.DENY


def test_many_run_tokens_stay_fast():
    # 1400 bytes of "run" tokens: the classifier must not explode combinatorially
    command = "execute " + "run " * 340 + "list"
    assert tier_of(command) is Tier.CONFIRM
    command = "execute run " * 116 + "list"
    assert tier_of(command) is Tier.DENY


@pytest.mark.parametrize(
    "command",
    [
        "ѕtop",  # Cyrillic ѕ (U+0455)
        "ЅTOP",  # Cyrillic Ѕ (U+0405)
        "ｓｔｏｐ",  # fullwidth
        "stoр",  # Cyrillic р (U+0440)
        "lіst",  # Cyrillic і (U+0456) in a read root
        "ѕay hi",
    ],
)
def test_unicode_lookalikes_do_not_match_and_fall_to_confirm(command):
    decision = classify(command, RW, POLICY)
    assert decision.tier is Tier.CONFIRM
    assert "unknown command" in decision.reason
    assert classify(command, RO, POLICY).allowed is False


def test_kelvin_sign_lowercases_to_hard_confirm_kill():
    # "K" (Kelvin sign) lower-cases to ASCII "k": it must not slip past the kill rule
    assert tier_of("KILL @e") is Tier.CONFIRM


@pytest.mark.parametrize(
    "command, tier",
    [
        # one leading "minecraft:" is the vanilla command itself
        ("minecraft:stop", Tier.CONFIRM),
        ("MINECRAFT:Stop", Tier.CONFIRM),
        ("minecraft:kill @e", Tier.CONFIRM),
        ("minecraft:debug start", Tier.DENY),
        ("minecraft:list", Tier.READ),
        ("Minecraft:LIST", Tier.READ),
        ("minecraft:say hi", Tier.WRITE),
        ("minecraft:say hi @a", Tier.WRITE),
        ("minecraft:tp @a 0 64 0", Tier.CONFIRM),
        ("minecraft:execute as @a run debug start", Tier.DENY),
        ("minecraft:execute if entity @e", Tier.READ),
        ("execute as @s run minecraft:list", Tier.READ),
        ("//minecraft:set", Tier.CONFIRM),
        # any other namespace is never trusted below confirm
        ("minecraft:minecraft:list", Tier.CONFIRM),  # only ONE minecraft: is removed
        ("bukkit:list", Tier.CONFIRM),
        ("evil:say hi", Tier.CONFIRM),
        ("bukkit:transfer x 1 Steve", Tier.DENY),
        ("evil:execute if entity @e", Tier.CONFIRM),
        ("evil:op Steve", Tier.CONFIRM),
    ],
)
def test_namespaced_roots(command, tier):
    assert tier_of(command) is tier


def test_minecraft_namespace_is_sent_as_given():
    assert classify("/minecraft:list", RW, POLICY).normalized == "minecraft:list"


@pytest.mark.parametrize("command", ["//set stone", "//pos1", "//wand", "//undo", "///x", "// /x"])
def test_worldedit_roots_always_confirm(command):
    decision = classify(command, RW, POLICY)
    assert decision.normalized.startswith("/")
    assert decision.tier is Tier.CONFIRM
    assert classify(command, RO, POLICY).allowed is False


def test_single_slash_pos1_is_plain_unknown():
    decision = classify("/pos1", RW, POLICY)
    assert decision.normalized == "pos1"
    assert decision.tier is Tier.CONFIRM


def test_worldedit_cannot_be_lowered_even_by_a_hand_built_policy():
    policy = Policy(read=("/set *", "//set *"))
    assert tier_of("//set stone", policy) is Tier.CONFIRM


# ------------------------------------------------------------------------------------------ selector escalation


@pytest.mark.parametrize(
    "command, tier",
    [
        ("tp @a 0 64 0", Tier.CONFIRM),
        ("tp @a[limit=1] 0 64 0", Tier.WRITE),
        ("tp @a[limit=10] 0 64 0", Tier.WRITE),
        ("tp @a[limit=11] 0 64 0", Tier.CONFIRM),  # a huge limit is not a bound
        ("tp @a[limit=99999] 0 64 0", Tier.CONFIRM),
        ("tp @a[limit=0] 0 64 0", Tier.CONFIRM),
        ("tp @a[limit=-1] 0 64 0", Tier.CONFIRM),
        ("tp @a[limit=x] 0 64 0", Tier.CONFIRM),
        ("tp @a[distance=..5] 0 64 0", Tier.CONFIRM),
        ("tp @a[sort=nearest,limit=1] 0 64 0", Tier.WRITE),
        ("tp @a[type=player] 0 64 0", Tier.CONFIRM),
        ("effect give @e[type=zombie] minecraft:speed", Tier.WRITE),
        ("effect give @e[type=#minecraft:skeletons] minecraft:speed", Tier.WRITE),
        ("effect give @e[type=zombie,limit=3] minecraft:speed", Tier.WRITE),
        ("effect give @e[limit=3] minecraft:speed", Tier.CONFIRM),  # @e needs type=
        ("effect give @e minecraft:speed", Tier.CONFIRM),
        ("effect give @e[type=!zombie] minecraft:speed", Tier.CONFIRM),  # negation is not a bound
        ("effect give @e[type=player] minecraft:speed", Tier.CONFIRM),  # same as @a
        ("effect give @e[type=minecraft:player] minecraft:speed", Tier.CONFIRM),
        ("effect give @e[type=player,limit=1] minecraft:speed", Tier.WRITE),
        # nested data or quoting could hide a fake limit=/type=: counted as unbounded
        ("tp @a[nbt={limit:1}] 0 64 0", Tier.CONFIRM),
        ("tp @a[scores={limit=1}] 0 64 0", Tier.CONFIRM),
        ('tp @a[name="limit=1"] 0 64 0', Tier.CONFIRM),
        ("tp @e[type=zombie,nbt={NoAI:1b}] 0 64 0", Tier.CONFIRM),
        ("tp @a[ limit=1] 0 64 0", Tier.CONFIRM),  # "@a[" alone: split by a space
        ("tp @a[ sort=nearest, limit=1] 0 64 0", Tier.CONFIRM),  # split by a space: not trusted
        ("tp @a[limit=1", Tier.CONFIRM),  # unterminated
        ("tp @A 0 64 0", Tier.CONFIRM),  # case does not help
        # @s, @p, @r, @n never escalate
        ("tp @s 0 64 0", Tier.WRITE),
        ("tp @p 0 64 0", Tier.WRITE),
        ("tp @r 0 64 0", Tier.WRITE),
        ("tp @n 0 64 0", Tier.WRITE),
        ("tp @n[type=zombie] @p", Tier.WRITE),
        # message commands: their own selectors pick an audience and do not escalate
        ("say hi @a", Tier.WRITE),
        ('tellraw @a {"text":"x"}', Tier.WRITE),
        ('title @a title "x"', Tier.WRITE),
        ("title @e[limit=3] actionbar hi", Tier.WRITE),
        ("playsound minecraft:block.bell.use master @a", Tier.WRITE),
        ("particle minecraft:flame ~ ~ ~ 1 1 1 0 10 force @a", Tier.WRITE),
        ("execute as @s run say hi @a", Tier.WRITE),
        ("give @a minecraft:diamond", Tier.CONFIRM),  # not a message command
        ("clear @a", Tier.CONFIRM),
        # an unbounded selector in the execute prefix escalates every wrapped write, messages included
        ("execute as @a run say hi", Tier.CONFIRM),
        ('execute at @e run tellraw @s {"text":"x"}', Tier.CONFIRM),
        ("execute as @a run tp @s 0 64 0", Tier.CONFIRM),
        ("execute as @a store result score @s x run data get entity @s Health", Tier.CONFIRM),
        ("execute as @a summon minecraft:zombie", Tier.CONFIRM),
        ("execute as @s run tp @a 0 64 0", Tier.CONFIRM),
        ("execute as @s run execute as @a run say hi", Tier.CONFIRM),
        ("execute as @e[type=zombie] run tp @s ~ ~1 ~", Tier.WRITE),
        ("execute as @a[limit=1] run tp @s 0 64 0", Tier.WRITE),
        # read tier is never escalated
        ("execute as @a run list", Tier.READ),
        ("data get entity @e[limit=1] Pos", Tier.READ),
    ],
)
def test_selector_escalation(command, tier):
    decision = classify(command, RW, POLICY)
    assert decision.tier is tier, decision
    if tier is Tier.CONFIRM and command.startswith(("tp @a", "effect")):
        assert "unbounded selector" in decision.reason


# ------------------------------------------------------------------------------------------ patterns


def test_question_mark_matches_exactly_one_token():
    policy = Policy(read=("foo ?",), write=("foo ? ?",))
    assert tier_of("foo a", policy) is Tier.READ
    assert tier_of("foo a b", policy) is Tier.WRITE
    assert tier_of("foo", policy) is Tier.CONFIRM
    assert tier_of("foo a b c", policy) is Tier.CONFIRM


def test_star_matches_one_or_more_tokens_only():
    policy = Policy(read=("foo *",))
    assert tier_of("foo a", policy) is Tier.READ
    assert tier_of("foo a b c", policy) is Tier.READ
    assert tier_of("foo", policy) is Tier.CONFIRM


def test_pattern_without_star_matches_whole_command():
    policy = Policy(read=("foo bar",))
    assert tier_of("foo bar", policy) is Tier.READ
    assert tier_of("foo bar baz", policy) is Tier.CONFIRM


def test_arguments_match_case_sensitively():
    assert tier_of("tick query") is Tier.READ
    assert tier_of("tick QUERY") is Tier.CONFIRM  # falls to "tick *"
    assert tier_of("data GET entity Bot1") is Tier.CONFIRM  # matches nothing


def test_most_specific_pattern_wins():
    assert tier_of("worldborder get") is Tier.READ
    assert tier_of("worldborder add 10") is Tier.CONFIRM
    assert tier_of("scoreboard players list Bot1") is Tier.READ
    assert tier_of("scoreboard players add Bot1 kills 1") is Tier.WRITE


def test_tie_goes_to_most_restrictive_tier():
    policy = Policy(read=("foo *",), write=("foo *",), confirm=("bar ?",), deny=("bar ?",))
    assert tier_of("foo x", policy) is Tier.WRITE
    assert tier_of("bar x", policy) is Tier.DENY


def test_hard_roots_enforced_even_in_hand_built_policy():
    policy = Policy(read=("stop", "op *", "debug *", "minecraft:op *"))
    assert tier_of("stop", policy) is Tier.CONFIRM
    assert tier_of("op Steve", policy) is Tier.CONFIRM
    assert tier_of("debug start", policy) is Tier.DENY
    assert tier_of("minecraft:op Steve", policy) is Tier.CONFIRM


# ------------------------------------------------------------------------------------------ default + merge


def test_default_policy_loads_four_tiers():
    assert isinstance(POLICY, Policy)
    assert "gamerule ?" in POLICY.read and "gamerule ? ?" in POLICY.write
    assert "tick query" in POLICY.read and "tick *" in POLICY.confirm
    for root in HARD_DENY:
        assert root in POLICY.deny


def test_message_roots():
    assert MESSAGE_ROOTS == frozenset({"say", "tellraw", "title", "playsound", "particle"})


def test_hard_sets():
    assert HARD_CONFIRM == frozenset({
        "stop", "op", "deop", "ban", "ban-ip", "pardon", "pardon-ip", "whitelist", "kick", "kill", "fill",
        "clone", "save-off", "reload", "lp", "luckperms", "perm",
    })
    assert HARD_DENY == frozenset({"debug", "perf", "jfr", "publish", "transfer"})


@pytest.mark.parametrize("root", sorted(HARD_CONFIRM))
@pytest.mark.parametrize("tier", ["read", "write"])
@pytest.mark.parametrize("shape", ["{root}", "{root} *", "{root} ?", "{ROOT} *", "minecraft:{root} *"])
def test_merge_refuses_lowering_hard_confirm(root, tier, shape):
    pattern = shape.format(root=root, ROOT=root.upper())
    with pytest.raises(ValueError):
        merge_policy(POLICY, {tier: [pattern]})


@pytest.mark.parametrize("root", sorted(HARD_DENY))
@pytest.mark.parametrize("tier", ["read", "write", "confirm"])
def test_merge_refuses_lowering_hard_deny(root, tier):
    for pattern in (root, f"{root} *", f"{root.upper()} start", f"minecraft:{root} *"):
        with pytest.raises(ValueError):
            merge_policy(POLICY, {tier: [pattern]})


@pytest.mark.parametrize("pattern", ["//set *", "/pos1", "/set stone"])
@pytest.mark.parametrize("tier", ["read", "write"])
def test_merge_refuses_lowering_worldedit(pattern, tier):
    with pytest.raises(ValueError):
        merge_policy(POLICY, {tier: [pattern]})


def test_merge_refuses_op_as_read_and_classify_unchanged():
    with pytest.raises(ValueError):
        merge_policy(POLICY, {"read": ["op *"]})
    assert tier_of("op Steve") is Tier.CONFIRM


@pytest.mark.parametrize(
    "extra",
    [
        {"read": ["execute *"]},  # execute is classified by its run remainder
        {"read": ["*"]},
        {"read": ["? status"]},
        {"read": ["mymod * status"]},  # '*' only as last token
        {"read": [""]},
        {"read": ["say\nstop"]},
        {"read": "mymod status *"},  # a bare string, not a list
        {"read": [42]},
        {"admin": ["mymod *"]},  # unknown tier key
    ],
)
def test_merge_rejects_malformed_extra(extra):
    with pytest.raises(ValueError):
        merge_policy(POLICY, extra)


def test_merge_accepts_custom_root():
    merged = merge_policy(POLICY, {"read": ["mymod status *"], "write": ["mymod boss reset *"]})
    assert tier_of("mymod status all", merged) is Tier.READ
    assert tier_of("mymod boss reset arena", merged) is Tier.WRITE
    assert tier_of("mymod nuke", merged) is Tier.CONFIRM
    assert tier_of("mymod status all", POLICY) is Tier.CONFIRM  # base is untouched
    assert merged.read[: len(POLICY.read)] == POLICY.read


def test_merge_can_raise_and_add_hard_roots_to_stricter_tiers():
    merged = merge_policy(POLICY, {"deny": ["stop", "tp *"], "confirm": ["op *"]})
    assert tier_of("stop", merged) is Tier.DENY
    assert tier_of("tp Bot1 0 64 0", merged) is Tier.DENY  # tie with the default "tp *": stricter wins
    assert tier_of("op Steve", merged) is Tier.CONFIRM


def test_merge_can_lower_a_non_hard_default():
    merged = merge_policy(POLICY, {"write": ["difficulty peaceful"]})
    assert tier_of("difficulty peaceful", merged) is Tier.WRITE
    assert tier_of("difficulty hard", merged) is Tier.CONFIRM


def test_merge_deduplicates():
    merged = merge_policy(POLICY, {"read": ["mymod status *", "mymod status *", "list"]})
    assert merged.read.count("mymod status *") == 1
    assert merged.read.count("list") == 1


# ------------------------------------------------------------------------------------------ selector limits


@pytest.mark.parametrize(
    "command, expected",
    [
        ("tp @p[limit=1000] 0 64 0", Tier.CONFIRM),   # any selector with limit above 10
        ("tp @r[limit=11] 0 64 0", Tier.CONFIRM),
        ("tp @n[type=zombie,limit=50] 0 64 0", Tier.CONFIRM),
        ("tp @s[limit=99] 0 64 0", Tier.CONFIRM),
        ("tp @p[limit=1,limit=2] 0 64 0", Tier.CONFIRM),  # limit= twice
        ("tp @a[limit=1,limit=2] 0 64 0", Tier.CONFIRM),
        ("tp @e[type=zombie,limit=1,limit=5] 0 64 0", Tier.CONFIRM),
        ("tp @p[nbt={a:1},limit=1000] 0 64 0", Tier.CONFIRM),  # unparseable and mentions limit
        ("tp @p[limit=10] 0 64 0", Tier.WRITE),
        ("tp @r[limit=3,sort=random] 0 64 0", Tier.WRITE),
        ("tp @p[distance=..5] 0 64 0", Tier.WRITE),          # no limit=: stays bounded
        ("tp @p[nbt={a:1}] 0 64 0", Tier.WRITE),
        ("tp @e[type=zombie,limit=1] 0 64 0", Tier.WRITE),
        ("say hi @p[limit=1000]", Tier.WRITE),                # message roots pick an audience
        ("execute as @p[limit=1000] run say hi", Tier.CONFIRM),
    ],
)
def test_selector_limit_rules(command, expected):
    assert tier_of(command) is expected


@pytest.mark.parametrize(
    "command, expected",
    [
        ("scoreboard players reset *", Tier.CONFIRM),
        ("scoreboard players set * kills 0", Tier.CONFIRM),
        ("scoreboard players operation @s kills += * kills", Tier.CONFIRM),
        ("execute store result score * kills run list", Tier.CONFIRM),
        ("scoreboard players list *", Tier.READ),             # a read never escalates
        ("scoreboard players set Bot1 kills 0", Tier.WRITE),
        ("scoreboard objectives add * dummy", Tier.WRITE),    # not a score holder
    ],
)
def test_scoreboard_wildcard_holder(command, expected):
    assert tier_of(command) is expected


# ------------------------------------------------------------------------------------------ tick


@pytest.mark.parametrize("command", ["tick freeze", "tick unfreeze", "tick sprint 100", "tick step 5",
                                     "tick rate 0.1", "tick sprint stop"])
def test_tick_forms_other_than_query_need_confirmation(command):
    assert tier_of(command) is Tier.CONFIRM
    assert tier_of("tick query") is Tier.READ


def test_operator_may_lower_tick_forms():
    merged = merge_policy(POLICY, {"write": ["tick freeze", "tick unfreeze"]})
    assert tier_of("tick freeze", merged) is Tier.WRITE
    assert tier_of("tick unfreeze", merged) is Tier.WRITE
    assert tier_of("tick sprint 100", merged) is Tier.CONFIRM


# ------------------------------------------------------------------------------------------ indirect execution


INDIRECT = [
    'setblock 0 64 0 minecraft:repeating_command_block{Command:"fill 0 0 0 9 9 9 air",auto:1b}',
    'summon command_block_minecart ~ ~ ~ {Command:"stop"}',
    "give @s minecraft:command_block",
    'data merge block 0 64 0 {Command:"stop"}',
    "data merge block 0 64 0 {'Command':\"stop\"}",          # single-quoted key
    'data merge block 0 64 0 {Command :"stop"}',             # space before the colon
    'data merge block 0 64 0 {"Command":"stop"}',
    'data modify block 0 64 0 Command set value "stop"',     # NBT path, no colon
    'data modify entity @s Passengers[0].Command set value "stop"',
    'tellraw Steve {"text":"x","clickEvent":{"action":"run_command","value":"/op Steve"}}',
    'tellraw Steve {"text":"x","click_event":{"action":"run_command","command":"/op Steve"}}',
    'tellraw Steve {"text":"x","clickEvent":{"action":"run_comm\\u0061nd","value":"/op Steve"}}',  # JSON escape
    'tellraw Steve {"text":"x","clickEvent":{"action":"run_comm\\x61nd","value":"/op Steve"}}',
    "tellraw Steve {\"text\":\"x\",\"clickEvent\":{\"action\":\"run_comm\\N{LATIN SMALL LETTER A}nd\"}}",
    'title @a title {"text":"x","clickEvent":{"action":"run_command","value":"/stop"}}',
    "execute as @s run give @s command_block",
    'item replace block 0 64 0 container.0 with written_book[written_book_content={pages:[{text:"x",'
    'click_event:{action:"run_command",command:"/op Eve"}}]}]',
    "say I typed a command: x",                               # accepted false positive
]


@pytest.mark.parametrize("command", INDIRECT)
def test_indirect_execution_needs_confirmation(command):
    decision = classify(command, RW, POLICY)
    assert decision.tier in (Tier.CONFIRM, Tier.DENY), (command, decision.reason)
    assert not decision.allowed


def test_indirect_reason_and_read_only_refusal():
    decision = classify("give @s command_block", RW, POLICY)
    assert decision.needs_confirmation and "indirect execution" in decision.reason
    refused = classify("give @s command_block", RO, POLICY)
    assert not refused.allowed and not refused.needs_confirmation


def test_indirect_markers_cannot_be_lowered_by_config():
    merged = merge_policy(POLICY, {"write": ["give @s command_block", "mymod store *"], "read": ["mymod show *"]})
    assert tier_of("give @s command_block", merged) is Tier.CONFIRM
    assert tier_of('mymod store {Command:"stop"}', merged) is Tier.CONFIRM
    assert tier_of("mymod show run_command", merged) is Tier.CONFIRM
    assert tier_of("mymod show x", merged) is Tier.READ


def test_indirect_markers_constant():
    assert INDIRECT_MARKERS == ("command_block", "run_command", "command:", '"command"')


@pytest.mark.parametrize("command", [
    "data get block 0 64 0 Command",     # reading a command block stays read
    'tellraw @a {"text":"hi"}',
    "say commands are fun",
    "give @s minecraft:stone",
    "setblock 0 64 0 minecraft:stone",
])
def test_no_indirect_false_positive_on_plain_commands(command):
    assert classify(command, RW, POLICY).allowed


def test_deny_is_never_lowered_by_the_indirect_rule():
    assert tier_of("debug start command_block") is Tier.DENY
