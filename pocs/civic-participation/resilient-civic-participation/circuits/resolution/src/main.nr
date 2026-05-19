use rcp_lib::cmp;
use rcp_lib::hasher;
use rcp_lib::merkle;

// Resolution SNARK (SPEC section Resolution SNARK).
//
// Iterates over all `leaf_count` leaves in `running_root`, recomputes
// `leaf_j = Poseidon1(DOMAIN_LEAF, nullifier_j, class_tag_j)` from the
// witnessed pair, opens each leaf at the IMT membership path, and
// tallies per-class counts. Outputs `b` and `b_per_class[i]`.
//
// We bound `leaf_count` at compile time to a max of `100_000` records
// (the SPEC permits up to `10 * sum(class_thresholds)` with no global
// cap; deployments choose a circuit size per expected participation).
// For the PoC integration test we instantiate a smaller variant via
// `LEAF_MAX = 200`. Tweak the constant below if larger fixtures are
// required.

global LEAF_MAX: u32 = 200;
global CLASS_MAX: u32 = 16;
global IMT_DEPTH: u32 = 24;

fn main(
    predicate_hash: pub Field,
    r_root: pub Field,
    running_root: pub Field,
    leaf_count: pub u32,
    class_set: pub [Field; CLASS_MAX],
    class_set_len: pub u32,
    class_thresholds: pub [u32; CLASS_MAX],
    b: pub Field,
    b_per_class: pub [Field; CLASS_MAX],
    // class_index is bound to the petition's stored value via the
    // Registry's _checkResolutionPriorState. The proof system commits
    // to this value; the resolution leaves carry their own class_tag,
    // so the circuit does not need to use class_index internally
    // beyond exposing it as a public input.
    class_index: pub Field,
    // Private
    nullifier: [Field; LEAF_MAX],
    class_tag: [Field; LEAF_MAX],
    imt_next_index: [Field; LEAF_MAX],
    imt_next_value: [Field; LEAF_MAX],
    imt_path_indices: [[bool; IMT_DEPTH]; LEAF_MAX],
    imt_path_elements: [[Field; IMT_DEPTH]; LEAF_MAX],
) {
    // Constraint 1: bound leaf_count.
    assert(leaf_count <= LEAF_MAX, "resolution: leaf_count > LEAF_MAX");
    assert(class_set_len <= CLASS_MAX, "resolution: class_set_len > CLASS_MAX");

    // Constraint 5: class_set strictly increasing.
    for i in 0..CLASS_MAX {
        if (i as u32) + 1 < class_set_len {
            let lt = cmp::lt_field(class_set[i], class_set[i + 1]);
            assert(lt, "resolution: class_set not strictly increasing");
        }
    }

    // Per-class counts.
    let mut counts: [u32; CLASS_MAX] = [0; CLASS_MAX];

    // Constraint 2-4: per-leaf membership in running_root with the
    // witnessed (nullifier_j, class_tag_j) pair. Constraint 6: each
    // active class_tag_j must lie in class_set; off-class leaves that
    // would otherwise be silently dropped from every count[k] are
    // rejected at proving time.
    for j in 0..LEAF_MAX {
        let active = (j as u32) < leaf_count;
        if active {
            let leaf_j = hasher::hash_leaf(nullifier[j], class_tag[j]);
            let imt_leaf = hasher::hash_imt_leaf(leaf_j, imt_next_index[j], imt_next_value[j]);
            merkle::verify_membership_depth_24(
                imt_leaf,
                running_root,
                IMT_DEPTH,
                imt_path_indices[j],
                imt_path_elements[j],
            );

            let mut found_in_class_set: bool = false;
            for k in 0..CLASS_MAX {
                let in_range = (k as u32) < class_set_len;
                let matches = class_tag[j] == class_set[k];
                if in_range & matches {
                    counts[k] = counts[k] + 1;
                    found_in_class_set = true;
                }
            }
            assert(found_in_class_set, "resolution: class_tag not in class_set");
        }
    }

    // Constraint 6: per-class boolean.
    let mut all_satisfied: bool = true;
    for k in 0..CLASS_MAX {
        let in_range = (k as u32) < class_set_len;
        let satisfies = counts[k] >= class_thresholds[k];
        let expected = if in_range {
            (if satisfies { 1 } else { 0 })
        } else {
            0
        };
        assert(b_per_class[k] == expected as Field, "resolution: b_per_class[k] mismatch");
        if in_range {
            all_satisfied = all_satisfied & satisfies;
        }
    }

    // Constraint 7: b = AND_i b_per_class[i].
    let expected_b: Field = if all_satisfied { 1 } else { 0 };
    assert(b == expected_b, "resolution: b mismatch");

    // Constraint 2 (pairwise distinct leaves) cross-check: leaves form
    // a strictly increasing sequence under canonical BN254 ordering.
    for j in 0..LEAF_MAX {
        let in_range = (j as u32) + 1 < leaf_count;
        if in_range {
            let lj = hasher::hash_leaf(nullifier[j], class_tag[j]);
            let lj1 = hasher::hash_leaf(nullifier[j + 1], class_tag[j + 1]);
            let lt = cmp::lt_field(lj, lj1);
            assert(lt, "resolution: leaves not strictly increasing");
        }
    }

    let _ = predicate_hash;
    let _ = r_root;
    let _ = class_index;
}
