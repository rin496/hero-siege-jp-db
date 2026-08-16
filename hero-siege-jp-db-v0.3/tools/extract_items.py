from pathlib import Path
import json

CSV = Path("translationsItem.csv")
OUT = Path("items.json")

lines = CSV.read_text(encoding="utf-8-sig", errors="replace").splitlines()
sections = []
for line in lines:
    first = line.split("|")[0].strip()
    if first.startswith("[") and first.endswith("]"):
        sections.append(first[1:-1])
equip_sections = set(sections[:40])

def classify(section):
    s = section.lower()
    rarity = "U" if "unique" in s else "N"
    slot, wt = "Other", ""
    if s.startswith("normal axes"): slot, wt = "Weapon", "Axe"
    elif s.startswith("normal maces"): slot, wt = "Weapon", "Mace"
    elif s.startswith("normal daggers"): slot, wt = "Weapon", "Dagger"
    elif s.startswith("normal swords"): slot, wt = "Weapon", "Sword"
    elif "weapon_melee" in s: slot, wt = "Weapon", "Melee"
    elif "weapon_throwing" in s: slot, wt = "Weapon", "Throwing"
    elif "weapon_spell" in s: slot, wt = "Weapon", "Spell"
    elif "weapon_bow" in s: slot, wt = "Weapon", "Bow"
    elif "weapon_claw" in s: slot, wt = "Weapon", "Claw"
    elif "weapon_polearm" in s or "weapon_spear" in s: slot, wt = "Weapon", "Polearm / Spear"
    elif "weapon_gun" in s: slot, wt = "Weapon", "Gun"
    elif "weapon_chainsaw" in s: slot, wt = "Weapon", "Chainsaw"
    elif "weapon_flask" in s: slot, wt = "Weapon", "Flask"
    elif "weapon_universal" in s: slot, wt = "Weapon", "Universal"
    elif s.startswith("armors"): slot = "Armor"
    elif s.startswith("helms"): slot = "Helm"
    elif s.startswith("gloves"): slot = "Gloves"
    elif s.startswith("boots"): slot = "Boots"
    elif s.startswith("amulets"): slot = "Amulet"
    elif s.startswith("charms"): slot = "Charm"
    elif s.startswith("shields"): slot = "Shield"
    elif s.startswith("rings"): slot = "Ring"
    elif s.startswith("belts"): slot = "Belt"
    return slot, rarity, wt

rows = []
section = None
for line in lines:
    parts = line.split("|")
    first = parts[0].strip()
    if first.startswith("[") and first.endswith("]"):
        section = first[1:-1]
        continue
    if section not in equip_sections or not first or first.startswith("lore_") or len(parts) < 12 or not parts[1].strip():
        continue
    slot, rarity, wt = classify(section)
    rows.append([first, parts[1].strip(), parts[6].strip(), slot, rarity, wt])

OUT.write_text(json.dumps({
    "meta": {"source": "Hero Siege game files / translationsItem.csv", "itemCount": len(rows)},
    "items": rows
}, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
print(f"wrote {len(rows)} items -> {OUT}")