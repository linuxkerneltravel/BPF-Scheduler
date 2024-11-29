#ifndef HASH_TABLE_H
#define HASH_TABLE_H

#define HASH_TABLE_SIZE 128
#define MAX_COLLISIONS 4
//#define HASH_TABLE_VALUE_SIZE (HASH_TABLE_SIZE * sizeof(unsigned int)) + (HASH_TABLE_SIZE * MAX_COLLISIONS * sizeof(unsigned int))
#define HASH_LIST_LENGTH (HASH_TABLE_SIZE * MAX_COLLISIONS)

struct hash_table{
    unsigned int hash_node[HASH_TABLE_SIZE][MAX_COLLISIONS];
    //unsigned int hash_node[HASH_LIST_LENGTH];
    //unsigned int collisions[HASH_TABLE_SIZE * MAX_COLLISIONS];
    unsigned int counts[HASH_TABLE_SIZE];// 记录每个冲突桶中的元素数量
    unsigned int last_valid_index;
    unsigned int padding; // 填充字段，确保总大小为2568字节
};

static void hash_table_init(struct hash_table *table) {
    table->last_valid_index = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        table->counts[i] = 0;
        for (int j = 0; j < MAX_COLLISIONS; j++) {
            table->hash_node[i][j] = (unsigned int)-1; 
        }
    }
}

// static void hash_table_init(struct hash_table *table) {
//     #pragma unroll
//     for (int i = 0; i < HASH_TABLE_SIZE; i++) {
//         table->counts[i] = 0;
//         //#pragma unroll
//         // for (int j = 0; j < MAX_COLLISIONS; j++) {
//         //     table->hash_node[i][j] = (unsigned int)-1; // 使用 -1 表示空值
//         // }
//     }
//     for(int i = 0;i < HASH_TABLE_SIZE * MAX_COLLISIONS;i++)
//         table->hash_node[i] = (unsigned int)-1;
// }



static unsigned int hash_func(unsigned int key) {
    return key % HASH_TABLE_SIZE;
}

static unsigned int hash_table_lookup(struct hash_table *table, unsigned int key, bool create) {
    unsigned int hash_index = hash_func(key); // 计算哈希索引
    if(hash_index >= HASH_TABLE_SIZE)
        return (unsigned int)-1;
    
    // 首先检查 `hash_node` 中是否已经存储了此 key
    // if (table->hash_node[hash_index] == key) {
    //     return table->hash_node[hash_index];
    // }

    for (int i = 0; i < table->counts[hash_index] && i < MAX_COLLISIONS; i++) {
        if (table->hash_node[hash_index][i] == key) {
            return table->hash_node[hash_index][i]; 
        }
    }
    
    if (create && table->counts[hash_index] < MAX_COLLISIONS) {
        // 如果找不到且需要插入新值
        table->hash_node[hash_index][table->counts[hash_index]] = key;
        table->counts[hash_index]++;
        if(hash_index > table->last_valid_index)
            table->last_valid_index = hash_index;
        return table->hash_node[hash_index][table->counts[hash_index] - 1]; 
    }
    
    return (unsigned int)-1; // 未找到且不插入
}

// static unsigned int hash_table_lookup(struct hash_table *table, unsigned int key, bool create) {
//     unsigned int hash_index = hash_func(key);  // 计算哈希索引
//     unsigned int start_index = hash_index * MAX_COLLISIONS;  // 计算起始位置

//     if(hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1;
//     unsigned int count = table->counts[hash_index];  // 当前桶中的元素数量

//     // 遍历冲突链，查找指定的键
//     for (unsigned int i = 0; i < count && i < MAX_COLLISIONS; i++) {
//         unsigned int idx = start_index + i;
//         if(idx >= HASH_TABLE_SIZE * MAX_COLLISIONS)
//             return (unsigned int)-1;

//         if (table->hash_node[idx] == key) {
//             return table->hash_node[idx];  // 找到返回
//         }
//     }

//     // 如果未找到并且允许创建新的条目
//     if (create && count < MAX_COLLISIONS) {
//         unsigned int new_index = start_index + count;
//         if(new_index >= HASH_TABLE_SIZE * MAX_COLLISIONS)
//             return (unsigned int)-1;

//         table->hash_node[new_index] = key;  // 插入新值
//         table->counts[hash_index]++;  // 更新元素数量
//         if (hash_index > table->last_valid_index) {
//             table->last_valid_index = hash_index;  // 更新最后有效索引
//         }
//         return table->hash_node[new_index];  // 返回插入的值
//     }

//     return (unsigned int)-1;  // 未找到且不插入
// }


// static int hash_table_insert(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if(hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1;
//     unsigned int count = table->counts[hash_index];
//     if(hash_table_lookup(table,key,false) == key){
//         return 1;// 防止重复插入
//     }

//     if (count < MAX_COLLISIONS) {
//         table->hash_node[hash_index][count] = key;
//         table->counts[hash_index]++;
//         if(hash_index > table->last_valid_index)
//             table->last_valid_index = hash_index;
//     } else {
//         return -1;
//     }
//     return 0;
// }

// static int hash_table_insert(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if (hash_index >= HASH_TABLE_SIZE)
//         return -1;

//     unsigned int start_index = hash_index * MAX_COLLISIONS;
//     unsigned int count = table->counts[hash_index];

//     // 查找是否已经存在，防止重复插入
//     if (hash_table_lookup(table, key, false) == key) {
//         return 1;  // 防止重复插入
//     }

//     // 如果当前桶的冲突链未满，则插入新值
//     if (count < MAX_COLLISIONS) {
//         unsigned int new_index = start_index + count;
//         if(new_index >= HASH_TABLE_SIZE * MAX_COLLISIONS)
//             return (unsigned int)-1;

//         table->hash_node[new_index] = key;  // 插入新值
//         table->counts[hash_index]++;  // 更新元素数量

//         // 更新最后有效索引
//         if (hash_index > table->last_valid_index) {
//             table->last_valid_index = hash_index;
//         }
//     } else {
//         return -1;  // 冲突链已满，无法插入
//     }

//     return 0;  // 成功插入
// }



// 删除键值对
// static int hash_table_delete(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key); // 计算哈希索引
//     if(hash_index >= HASH_TABLE_SIZE)
//         return -1;
//     for (int i = 0; i < table->counts[hash_index] && i < MAX_COLLISIONS; i++) {
//         if (table->hash_node[hash_index][i] == key) {
//             // 将最后一个元素移动到被删除的位置，以保持连续性
//             // table->hash_node[hash_index][i] = table->hash_node[hash_index][table->counts[hash_index] - 1];
//             // table->hash_node[hash_index][table->counts[hash_index] - 1] = (unsigned int)-1; 
//             // table->counts[hash_index]--; 

//             // if (hash_index == table->last_valid_index && table->counts[hash_index] == 0) {
//             //     while (table->last_valid_index > 0 && table->counts[table->last_valid_index] == 0) {
//             //         table->last_valid_index--;
//             //     }
//             // }
//             // return 0;// 成功删除
//             if (table->counts[hash_index] > 0 && table->counts[hash_index] <= MAX_COLLISIONS){
//                 table->hash_node[hash_index][i] = table->hash_node[hash_index][table->counts[hash_index] - 1];
//                 table->hash_node[hash_index][table->counts[hash_index] - 1] = (unsigned int)-1; 
//                 table->counts[hash_index]--; 
                
//                 // 检查 table->last_valid_index 的合法性
//                 if (hash_index == table->last_valid_index && table->counts[hash_index] == 0) {
//                     while (table->last_valid_index > 0 && table->counts[table->last_valid_index] == 0) {
//                         table->last_valid_index--;
//                     }
//                 }   
//                 return 0; // 成功删除
//             }
//             else{
//                 return -1;
//             }
//         }
//     }
//     return 1;// 没找到
// }

static int hash_table_delete(struct hash_table *table, unsigned int key) {
    unsigned int hash_index = hash_func(key); // 计算哈希索引

    // 检查 hash_index 的合法性
    if (hash_index >= HASH_TABLE_SIZE)
        return -1;

    // 获取 counts[hash_index] 的值
    int count = table->counts[hash_index];

    // 检查 counts[hash_index] 是否在合法范围内
    // 因为要删除，所以count一定要大于0
    if (count <= 0 || count > MAX_COLLISIONS)
        return -1;

    // 遍历哈希链表
    #pragma unroll
    for (int i = 0; i < MAX_COLLISIONS; i++) {
        if (i >= count)
            break;

        // 检查 i 的范围
        if (i < 0 || i >= MAX_COLLISIONS)
            return -1;

        if (table->hash_node[hash_index][i] == key) {
            // 在使用 counts[hash_index] - 1 之前，再次检查
            if (count <= 0 || count > MAX_COLLISIONS)
                return -1;

            int last_index = count - 1;

            // 检查 last_index 的范围
            if (last_index < 0 || last_index >= MAX_COLLISIONS)
                return -1;

            // 将最后一个元素移动到被删除的位置，以保持连续性
            table->hash_node[hash_index][i] = table->hash_node[hash_index][last_index];
            table->hash_node[hash_index][last_index] = (unsigned int)-1;
            table->counts[hash_index]--;

            // 更新 count 的值
            count = table->counts[hash_index];

            // 更新 last_valid_index
            // if (hash_index == table->last_valid_index && count == 0) {
            //     while (table->last_valid_index > 0 && table->counts[table->last_valid_index] == 0) {
            //         table->last_valid_index--;
            //     }
            // }
            if (hash_index == table->last_valid_index && count == 0) {
                if (table->last_valid_index > 0 && table->last_valid_index < HASH_TABLE_SIZE) {
                // 使用固定次数的循环，展开循环以满足验证器的要求
                #pragma unroll
                for (int idx = 0; idx < HASH_TABLE_SIZE; idx++) {
                    if (table->last_valid_index == 0)
                        break;

                    // 检查 last_valid_index 的合法性
                    if (table->last_valid_index <= 0 || table->last_valid_index > HASH_TABLE_SIZE)
                        break;

                    // 检查 counts 数组访问的合法性
                    if (table->last_valid_index >= HASH_TABLE_SIZE)
                        break;

                    if (table->counts[table->last_valid_index] != 0)
                        break;

                    table->last_valid_index--;
                }
            }
        }

            return 0; // 成功删除
        }
    }
    return 1; // 没找到
}

// static int hash_table_delete(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);  // 计算哈希索引

//     // 检查 hash_index 的合法性
//     if (hash_index >= HASH_TABLE_SIZE) {
//         return -1;
//     }

//     // 获取桶中元素数量
//     int count = table->counts[hash_index];

//     // 检查 count 是否在合法范围内
//     if (count <= 0 || count > MAX_COLLISIONS) {
//         return -1;
//     }

//     // 计算当前桶的起始位置
//     unsigned int start_index = hash_index * MAX_COLLISIONS;

//     // 遍历哈希链表以查找待删除的元素
//     #pragma unroll
//     for (int i = 0; i < MAX_COLLISIONS; i++) {
//         if (i >= count) {
//             break;  // 没有更多元素可遍历
//         }

//         unsigned int current_index = start_index + i;

//         if (table->hash_node[current_index] == key) {
//             // 在使用 counts[hash_index] - 1 之前，再次检查
//             if (count <= 0 || count > MAX_COLLISIONS) {
//                 return -1;
//             }

//             int last_index = count - 1;
//             unsigned int last_elem_index = start_index + last_index;

//             // 检查 last_index 的范围
//             if (last_index < 0 || last_elem_index >= HASH_TABLE_SIZE * MAX_COLLISIONS) {
//                 return -1;
//             }

//             // 将最后一个元素移动到被删除的位置，以保持连续性
//             table->hash_node[current_index] = table->hash_node[last_elem_index];
//             table->hash_node[last_elem_index] = (unsigned int)-1;  // 清空最后一个元素
//             table->counts[hash_index]--;

//             // 更新 count 的值
//             count = table->counts[hash_index];

//             // 更新 last_valid_index
//             if (hash_index == table->last_valid_index && count == 0) {
//                 if (table->last_valid_index > 0 && table->last_valid_index < HASH_TABLE_SIZE) {
//                     // 使用固定次数的循环，以满足验证器的要求
//                     #pragma unroll
//                     for (int idx = 0; idx < HASH_TABLE_SIZE; idx++) {
//                         if (table->last_valid_index == 0) {
//                             break;
//                         }

//                         // 检查 last_valid_index 的合法性
//                         if (table->last_valid_index <= 0 || table->last_valid_index >= HASH_TABLE_SIZE) {
//                             break;
//                         }

//                         if (table->counts[table->last_valid_index] != 0) {
//                             break;
//                         }

//                         table->last_valid_index--;
//                     }
//                 }
//             }

//             return 0;  // 成功删除
//         }
//     }

//     return 1;  // 没找到
// }



// 返回key之后的下一个有效元素，遍历用，返回(unsigned int)-1表示到尾巴了
// static unsigned int hash_table_foreach(struct hash_table *table,unsigned int key){
//     unsigned int hash_index = hash_func(key); 
//     if(hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1;
//     bool found = false;

//     for (unsigned int i = hash_index; i <= table->last_valid_index && i < HASH_TABLE_SIZE; i++) {
//         for (unsigned int j = 0; j < table->counts[i] && j<MAX_COLLISIONS; j++){
//             if (found) {
//                 return table->hash_node[i][j]; 
//             }
//             if (table->hash_node[i][j] == key) {
//                 found = true; 
//             }
//         }
//     }
//     return (unsigned int)-1;
// }

// static unsigned int hash_table_foreach(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if (hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1;
//     int found = 0;

//     #pragma unroll 
//     for (int i = 0; i < HASH_TABLE_SIZE - hash_index; i++) {
//         unsigned int idx = hash_index + i;
//         if (idx >= HASH_TABLE_SIZE || idx > table->last_valid_index)
//             return (unsigned int)-1;

//         // if ((void *)&table->counts[idx] + sizeof(unsigned int) > (void *)table + HASH_TABLE_VALUE_SIZE)
//         //     return (unsigned int)-1;

//         if (idx * sizeof(unsigned int) >= HASH_TABLE_VALUE_SIZE)
//             return (unsigned int)-1;

//         unsigned int count = table->counts[idx];

//         if (count == 0)
//             continue;

//         if (count > MAX_COLLISIONS)
//             count = MAX_COLLISIONS;

//         #pragma unroll 
//         for (unsigned int j = 0; j < MAX_COLLISIONS; j++) {
//             if (j >= count || j>=MAX_COLLISIONS)
//                 break;

//             // if (idx >= HASH_TABLE_SIZE)
//             //     return (unsigned int)-1;
//             if ((idx * MAX_COLLISIONS + j) * sizeof(unsigned int) >= HASH_TABLE_VALUE_SIZE)
//                 return (unsigned int)-1;
            
//             //unsigned int *data = table->hash_node[idx];

//             if (found) {
//                 if(j < MAX_COLLISIONS && j<count)
//                     return table->hash_node[idx][j];
//                 break;
//             }

//             if (table->hash_node[idx][j] == key) {
//                 found = 1;
//             }
//         }
//     }
//     return (unsigned int)-1;
// }


// static unsigned int hash_table_foreach(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if (hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1; // 检查哈希索引的合法性

//     int found = 0; // 标记是否找到 key
//     unsigned int max_index = (table->last_valid_index + 1) * MAX_COLLISIONS;    

//     unsigned int current_index=0,value=(unsigned int)-1;

//     #pragma unroll
//     for (unsigned int i = hash_index * MAX_COLLISIONS; i < max_index && i < 512; i++) {
//         // 使用取模操作来确保索引在合法范围内
//         //unsigned int current_index = i % (HASH_TABLE_SIZE * MAX_COLLISIONS);
//         current_index = i;

//         // 提前结束遍历，如果当前索引超过了最大有效索引
//         if (current_index >= max_index)
//             return (unsigned int)-1;

//         current_index &= (HASH_LIST_LENGTH - 1); // 强制限制在 [0, 511]
//         // if(current_index >= HASH_TABLE_SIZE * MAX_COLLISIONS)
//         //     return (unsigned int)-1;
//         if(current_index < 512){
//             value = table->hash_node[current_index];
//             if (found && value != (unsigned int)-1) {
//                 return value;
//             }

//             // 检查当前值是否等于 key
//             if (value == key) {
//                 found = 1; // 标记已找到 key
//             }
//         }
//         else
//         {  
//             return (unsigned int)-1;
//         }
//         //value = table->hash_node[current_index];
//         // if(i >= HASH_TABLE_SIZE * MAX_COLLISIONS)
//         //     return (unsigned int)-1;
//         // unsigned int value = table->hash_node[i];

//         // 如果找到之前标记的 key，返回找到的下一个有效值
//         // if (found && value != (unsigned int)-1) {
//         //     return value;
//         // }

//         // // 检查当前值是否等于 key
//         // if (value == key) {
//         //     found = 1; // 标记已找到 key
//         // }
//     }

//     return (unsigned int)-1; // 未找到下一个有效元素
// }

// static unsigned int hash_table_foreach(struct hash_table *table, unsigned int key) {
//     unsigned int hash_index = hash_func(key);
//     if (hash_index >= HASH_TABLE_SIZE)
//         return (unsigned int)-1; 

//     if(table->last_valid_index >= HASH_TABLE_SIZE)
//         table->last_valid_index = HASH_TABLE_SIZE - 1;
//     unsigned int max_index = (table->last_valid_index + 1) * MAX_COLLISIONS;
//     if(max_index > HASH_LIST_LENGTH)
//         max_index = HASH_LIST_LENGTH;
//     unsigned int current_index = hash_index * MAX_COLLISIONS; // 从 key 的哈希槽起始位置开始
//     unsigned int value = (unsigned int)-1;
//     int found = 0; // 标记是否找到当前 key

//     //#pragma unroll
//     for (unsigned int i = current_index; i < HASH_LIST_LENGTH; i++) {
//         if(i >= max_index)
//             return (unsigned int)-1;
//         // 强制限制 current_index 的范围
//         //current_index = i & (HASH_LIST_LENGTH - 1); 
//         current_index = i;

//         // 检查偏移是否合法，避免越界访问
//         // unsigned int offset = current_index * sizeof(unsigned int);
//         // if (offset + sizeof(unsigned int) > sizeof(table->hash_node))
//         //     return (unsigned int)-1;

//         value = table->hash_node[current_index];

//         if (found && value != (unsigned int)-1) {
//             // 找到下一个有效值，返回
//             return value;
//         }

//         if (value == key) {
//             // 标记找到 key
//             found = 1;
//         }
//     }

//     return (unsigned int)-1; // 未找到下一个有效值
// }





#endif // HASH_TABLE_H