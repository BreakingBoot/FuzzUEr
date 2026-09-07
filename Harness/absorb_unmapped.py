# An unmapped *physical* access halts the whole campaign: simics raises a simulator error
# rather than a CPU exception, tsffs scores only exceptions 6/12/13/14, so the simulation
# stops "without reason, not resuming" and the script is interrupted -- with status 0, so
# it reads as a clean finish. Across matrix v7 the protocols that produced solutions
# averaged 540 iterations and those that produced none averaged 3373: the campaigns that
# find things are the ones being cut short.
#
# Backing the whole address space with a default_target stops that but breaks the boot:
# firmware probes for devices by reading and testing for all-ones, a ram object reads back
# as zeroes, and absent devices start looking present. That run had not reached the harness
# after 1139s where a normal boot takes ~560s.
#
# So absorb only what sits above everything the board actually maps, and take the boundary
# from the memory map rather than guessing it -- a hand-picked 32 GiB base still let a stop
# at 0x600014242 (25.8 GiB) through. Every stop observed in practice is a wild pointer
# between 25 GiB and 508 GiB, all under 2^39, which is the physical address width this cpu
# reports. Real RAM and MMIO stay below the boundary, so device probing is untouched.
# Simics images are sparse, so the window costs nothing until it is written.
import simics

GiB = 1 << 30
LIMIT = 1 << 46          # generously past the cpu's physical address width
FLOOR = 4 * GiB          # never absorb below 4 GiB whatever the map says


def top_of_map(mem):
    top = 0
    for entry in mem.map:
        try:
            top = max(top, entry[0] + entry[4])
        except (IndexError, TypeError):
            continue
    return top


try:
    core = conf.qsp.mb.cpu0.core[0][0]
    mem = core.physical_memory
    base = max(top_of_map(mem), FLOOR)
    base = (base + GiB - 1) & ~(GiB - 1)      # round up to a whole GiB
    size = LIMIT - base
    img = simics.SIM_create_object('image', 'unmapped_absorb_img', [['size', size]])
    # a ram object without a queue aborts simics outright:
    #   ASSERTION ERROR: Ram object unmapped_absorb_ram needs an associated clock
    ram = simics.SIM_create_object('ram', 'unmapped_absorb_ram',
                                   [['image', img], ['queue', core]])
    mem.map = mem.map + [[base, ram, 0, 0, size]]
    print('FUZZUER: absorbing unmapped accesses in [0x%x, 0x%x) -- board maps up to 0x%x'
          % (base, base + size, top_of_map(mem)))
except Exception as exc:
    print('FUZZUER: could not install unmapped-access absorber: %r' % (exc,))
