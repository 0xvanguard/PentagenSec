#ifndef __ML_KERN_H__
#define __ML_KERN_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "ml_weights.h"

struct ml_ctx {
    __s32 score;
    const __s32 *feat;
};

// Se pasa idx por bpf_loop. Como los árboles son completos y están
// ordenados secuencialmente, para el i-ésimo árbol, el índice base del nodo es:
// i * ((1 << ML_MAX_DEPTH) - 1). Y la hoja está en i * (1 << ML_MAX_DEPTH).
// Pero para bpf_loop, idx va de 0 a ML_N_TREES - 1.

static int ml_walk_tree(__u32 tree_idx, void *ctx) {
    struct ml_ctx *mc = ctx;
    
    // Inicio del arbol en el array (nodos internos)
    __u32 node_offset = tree_idx * ((1 << ML_MAX_DEPTH) - 1);
    __u32 leaf_offset = tree_idx * (1 << ML_MAX_DEPTH);
    
    __u32 curr = 0; // indice local dentro del arbol (0 a 2^D-2)
    
    // bpf_loop o unroll local para descender la profundidad
    #pragma unroll
    for (int d = 0; d < ML_MAX_DEPTH; d++) {
        if (node_offset + curr < sizeof(ml_tree_nodes)) {
            __s8 node = ml_tree_nodes[node_offset + curr];
            __u8 feat_id = (node >> 4) & 0x0F;
            __s8 thresh = node & 0x0F;
            
            if (feat_id < ML_N_FEATURES) {
                if (mc->feat[feat_id] <= thresh) {
                    curr = curr * 2 + 1; // Left
                } else {
                    curr = curr * 2 + 2; // Right
                }
            } else {
                break; // Corrupt node
            }
        }
    }
    
    // Al salir del loop, curr es el id del nodo en el nivel de hojas
    // En un arreglo de árbol binario perfecto, las hojas para la profundidad D
    // comienzan en el índice (2^D) - 1 si contáramos desde 0, 
    // pero aquí tenemos arreglos separados para nodos y hojas.
    // El índice local de la hoja es curr - ((1 << ML_MAX_DEPTH) - 1)
    __u32 local_leaf = curr - ((1 << ML_MAX_DEPTH) - 1);
    
    if (leaf_offset + local_leaf < sizeof(ml_leaf_vals)) {
        mc->score += ml_leaf_vals[leaf_offset + local_leaf];
    }
    
    return 0; // continuar al siguiente árbol
}

#endif // __ML_KERN_H__
