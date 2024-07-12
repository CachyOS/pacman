/*
 *  cpu_capabilities.c
 *
 *  Copyright (c) 2022-2023 by Vladislav Nepogodin <vnepogodin@cachyos.org>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/utsname.h> /* uname */

/* libalpm */
#include "alpm_list.h"
#include "log.h"
#include "util.h"

#if !defined(__aarch64__)

static uint64_t xgetbv(void) {
#if defined(_MSC_VER)
  return _xgetbv(0);
#else
  uint32_t eax = 0, edx = 0;
  __asm__ __volatile__("xgetbv\n" : "=a"(eax), "=d"(edx) : "c"(0));
  return ((uint64_t)edx << 32) | eax;
#endif
}

static void cpuid(uint32_t out[4], uint32_t id) {
#if defined(_MSC_VER)
  __cpuid((int *)out, id);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id));
#endif
}

static void cpuidex(uint32_t out[4], uint32_t id, uint32_t sid) {
#if defined(_MSC_VER)
  __cpuidex((int *)out, id, sid);
#elif defined(__i386__) || defined(_M_IX86)
  __asm__ __volatile__("movl %%ebx, %1\n"
                       "cpuid\n"
                       "xchgl %1, %%ebx\n"
                       : "=a"(out[0]), "=r"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#else
  __asm__ __volatile__("cpuid\n"
                       : "=a"(out[0]), "=b"(out[1]), "=c"(out[2]), "=d"(out[3])
                       : "a"(id), "c"(sid));
#endif
}

enum cpu_feature {
  SSE2 = 1 << 0,
  SSSE3 = 1 << 1,
  SSE41 = 1 << 2,
  SSE42 = 1 << 3,
  AVX = 1 << 4,
  AVX2 = 1 << 5,
  AVX512F = 1 << 6,
  AVX512BW = 1 << 7,
  AVX512CD = 1 << 8,
  AVX512DQ = 1 << 9,
  AVX512VL = 1 << 10,
  /* ... */
  UNDEFINED = 1 << 30
};

static enum cpu_feature g_cpu_features = UNDEFINED;

static enum cpu_feature get_cpu_features(void) {
  if (g_cpu_features != UNDEFINED) {
    return g_cpu_features;
  }
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
  uint32_t regs[4] = {0};
  uint32_t *eax = &regs[0], *ebx = &regs[1], *ecx = &regs[2], *edx = &regs[3];
  (void)edx;
  enum cpu_feature features = 0;
  cpuid(regs, 0);
  const int max_id = *eax;
  cpuid(regs, 1);
#if defined(__amd64__) || defined(_M_X64)
  features |= SSE2;
#else
  if (*edx & (1UL << 26))
    features |= SSE2;
#endif
  if (*ecx & (1UL << 0))
    features |= SSSE3;
  if (*ecx & (1UL << 19))
    features |= SSE41;
  if (*ecx & (1UL << 20))
    features |= SSE42;

  if (*ecx & (1UL << 27)) { // OSXSAVE
    const uint64_t mask = xgetbv();
    if ((mask & 6) == 6) { // SSE and AVX states
      if (*ecx & (1UL << 28))
        features |= AVX;
      if (max_id >= 7) {
        cpuidex(regs, 7, 0);
        if (*ebx & (1UL << 5))
          features |= AVX2;
        if ((mask & 224) == 224) { // Opmask, ZMM_Hi256, Hi16_Zmm
          if (*ebx & (1UL << 31))
            features |= AVX512VL;
          if (*ebx & (1UL << 16))
            features |= AVX512F;
          if (*ebx & (1UL << 30))
            features |= AVX512BW;
          if (*ebx & (1UL << 28))
            features |= AVX512CD;
          if (*ebx & (1UL << 17))
            features |= AVX512DQ;
        }
      }
    }
  }
  g_cpu_features = features;
  return features;
#else
  /* How to detect NEON? */
  return 0;
#endif
}

#endif

alpm_list_t SYMEXPORT *alpm_option_get_physical_architectures(alpm_handle_t *handle)
{
    alpm_list_t *supported_architectures = NULL;

    {
        struct utsname un;
        uname(&un);

        supported_architectures = alpm_list_add(supported_architectures, strdup(un.machine));
    }

#if !defined(__aarch64__)
    const enum cpu_feature features = get_cpu_features();

    /* Check for x86_64_v2 */
    const bool supports_v2 = (features & SSSE3) && (features & SSE41) && (features & SSE42);
    if (supports_v2) {
        _alpm_log(handle, ALPM_LOG_DEBUG, "cpu supports x86_64_v2\n");
        supported_architectures = alpm_list_add(supported_architectures, strdup("x86_64_v2"));
    }

    /* Check for x86_64_v3 */
    const bool supports_v3 = (supports_v2) && (features & AVX) && (features & AVX2);
    if (supports_v3) {
        _alpm_log(handle, ALPM_LOG_DEBUG, "cpu supports x86_64_v3\n");
        supported_architectures = alpm_list_add(supported_architectures, strdup("x86_64_v3"));
    }

    /* Check for x86_64_v4 */
    const bool supports_v4 = (supports_v3) && (features & AVX512F) && (features & AVX512VL) && (features & AVX512BW) && (features & AVX512CD) && (features & AVX512DQ);
    if (supports_v4) {
        _alpm_log(handle, ALPM_LOG_DEBUG, "cpu supports x86_64_v4\n");
        supported_architectures = alpm_list_add(supported_architectures, strdup("x86_64_v4"));
    }
#endif

    return supported_architectures;
}
