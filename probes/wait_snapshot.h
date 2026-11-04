#ifndef WAIT_SNAPSHOT_H
#define WAIT_SNAPSHOT_H

/* Shared word order for the C reader and DTrace producer. */
#define WAIT_FIELD_LIST(X, context) \
  X(context, sample_timestamp_ns, 0) \
  X(context, profile_generation, 1) \
  X(context, pid, 2) \
  X(context, tid, 3) \
  X(context, rip, 4) \
  X(context, rbp, 5) \
  X(context, rbx, 6) \
  X(context, rsp, 7) \
  X(context, cs, 8) \
  X(context, rflags, 9) \
  X(context, frame, 10) \
  X(context, base, 11) \
  X(context, top, 12) \
  X(context, parent, 13) \
  X(context, return_pc, 14) \
  X(context, requested, 15) \
  X(context, called, 16) \
  X(context, parent_called, 17) \
  X(context, response_before, 18) \
  X(context, response_after, 19) \
  X(context, action, 20) \
  X(context, action_arg0, 21) \
  X(context, action_arg1, 22) \
  X(context, mode, 23) \
  X(context, slide, 24)

#define WAIT_FIELD_COUNT 25
#define WAIT_ZERO_MASK ((1ULL << WAIT_FIELD_COUNT) - 1ULL)
#define WAIT_SLOT_WORDS (WAIT_FIELD_COUNT + 6)
#define WAIT_SLOT_BYTES (WAIT_SLOT_WORDS * 8)
#define WAIT_PAGE_OFFSET 288
#define WAIT_MAGIC 0x504353414d504c32ULL
#define WAIT_UNSLID_IDLE 0xffffff80003eed80ULL
#define WAIT_UNSLID_SYNC_RETURN 0xffffff80003f8c96ULL
#define WAIT_UNSLID_ASYNC_RETURN 0xffffff80003f8e41ULL
#define WAIT_SAFE_PC(pc, slide) \
  ((pc) == (slide) + 0xffffff80003f91a0ULL || \
   (pc) == (slide) + 0xffffff80003f91a3ULL || \
   (pc) == (slide) + 0xffffff80003f91a7ULL || \
   (pc) == (slide) + 0xffffff80003f91c0ULL || \
   (pc) == (slide) + 0xffffff80003f91c2ULL || \
   (pc) == (slide) + 0xffffff80003f91c7ULL || \
   (pc) == (slide) + 0xffffff80003f91c9ULL)

#endif
