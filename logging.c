/*
 * Copyright 2011 Daniel Drown
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * logging.c - print a log message
 */

#include <stdarg.h>
#include <android/log.h>

#include "logging.h"

void logmsg(int prio, const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  __android_log_vprint(prio, "clatd", fmt, ap);
  va_end(ap);
}
