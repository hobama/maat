#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include "expression.hpp"

#include <cstdint>
#include <unordered_map>

using std::unordered_map;

/* Memory */
typedef uint64_t addr_t;
typedef uint64_t offset_t;
typedef uint16_t segment_flags_t;
typedef uint8_t mem_alert_t;
typedef unordered_map<offset_t, std::pair<Expr,int>> symbolic_mem_map_t;

/* IR */
typedef unsigned int IRBasicBlockId;

#endif 
