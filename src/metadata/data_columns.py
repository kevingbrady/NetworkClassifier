import tensorflow as tf
import numpy as np

# Types for Non normalized data
columns = {
    'src_ip': np.str_,
    'dst_ip': np.str_,
    'src_port': np.int32,
    'dst_port': np.int32,
    'protocol': np.int32,
    'pkt_length': np.int32,
    'info': np.float64,
    'timestamp': np.float64,
    'flow_duration': np.float64,
    'flow_byts_s': np.float64,
    'flow_pkts_s': np.float64,
    'fwd_pkts_s': np.float64,
    'bwd_pkts_s': np.float64,
    'tot_fwd_pkts': np.float64,
    'tot_bwd_pkts': np.float64,
    'totlen_fwd_pkts': np.float64,
    'totlen_bwd_pkts': np.float64,
    'fwd_pkt_len_max': np.float64,
    'fwd_pkt_len_min': np.float64,
    'fwd_pkt_len_mean': np.float64,
    'fwd_pkt_len_std': np.float64,
    'bwd_pkt_len_max': np.float64,
    'bwd_pkt_len_min': np.float64,
    'bwd_pkt_len_mean': np.float64,
    'bwd_pkt_len_std': np.float64,
    'pkt_len_max': np.float64,
    'pkt_len_min': np.float64,
    'pkt_len_mean': np.float64,
    'pkt_len_std': np.float64,
    'pkt_len_var': np.float64,
    'fwd_header_len': np.int32,
    'bwd_header_len': np.int32,
    'fwd_seg_size_min': np.float64,
    'fwd_act_data_pkts': np.float64,
    'flow_iat_mean': np.float64,
    'flow_iat_max': np.float64,
    'flow_iat_min': np.float64,
    'flow_iat_std': np.float64,
    'fwd_iat_tot': np.float64,
    'fwd_iat_max': np.float64,
    'fwd_iat_min': np.float64,
    'fwd_iat_mean': np.float64,
    'fwd_iat_std': np.float64,
    'bwd_iat_tot': np.float64,
    'bwd_iat_max': np.float64,
    'bwd_iat_min': np.float64,
    'bwd_iat_mean': np.float64,
    'bwd_iat_std': np.float64,
    'fwd_psh_flags': np.int32,
    'bwd_psh_flags': np.int32,
    'fwd_urg_flags': np.int32,
    'bwd_urg_flags': np.int32,
    'fin_flag_cnt': np.int32,
    'syn_flag_cnt': np.int32,
    'rst_flag_cnt': np.int32,
    'psh_flag_cnt': np.int32,
    'ack_flag_cnt': np.int32,
    'urg_flag_cnt': np.int32,
    'ece_flag_cnt': np.int32,
    'down_up_ratio': np.float64,
    'pkt_size_avg': np.float64,
    'init_fwd_win_byts': np.float64,
    'init_bwd_win_byts': np.float64,
    'active_max': np.float64,
    'active_min': np.float64,
    'active_mean': np.float64,
    'active_std': np.float64,
    'idle_max': np.float64,
    'idle_min': np.float64,
    'idle_mean': np.float64,
    'idle_std': np.float64,
    'fwd_byts_b_avg': np.float64,
    'fwd_pkts_b_avg': np.float64,
    'bwd_byts_b_avg': np.float64,
    'bwd_pkts_b_avg': np.float64,
    'fwd_blk_rate_avg': np.float64,
    'bwd_blk_rate_avg': np.float64,
    'Target': np.int32
}

# Types for normalized data
columns_normalized = {
    "No": np.int32,
    "src_ip": np.float64,
    "dst_ip": np.float64,
    "src_port": np.float64,
    "dst_port": np.float64,
    "protocol": np.float64,
    "pkt_length": np.float64,
    "info": np.float64,
    "timestamp": np.float64,
    "flow_duration": np.float64,
    "flow_byts_s": np.float64,
    "flow_pkts_s": np.float64,
    "fwd_pkts_s": np.float64,
    "bwd_pkts_s": np.float64,
    "tot_fwd_pkts": np.float64,
    "tot_bwd_pkts": np.float64,
    "totlen_fwd_pkts": np.float64,
    "totlen_bwd_pkts": np.float64,
    "fwd_pkt_len_max": np.float64,
    "fwd_pkt_len_min": np.float64,
    "fwd_pkt_len_mean": np.float64,
    "fwd_pkt_len_std": np.float64,
    "bwd_pkt_len_max": np.float64,
    "bwd_pkt_len_min": np.float64,
    "bwd_pkt_len_mean": np.float64,
    "bwd_pkt_len_std": np.float64,
    "pkt_len_max": np.float64,
    "pkt_len_min": np.float64,
    "pkt_len_mean": np.float64,
    "pkt_len_std": np.float64,
    "pkt_len_var": np.float64,
    "fwd_header_len": np.float64,
    "bwd_header_len": np.float64,
    "fwd_seg_size_min": np.float64,
    "fwd_act_data_pkts": np.float64,
    "flow_iat_mean": np.float64,
    "flow_iat_max": np.float64,
    "flow_iat_min": np.float64,
    "flow_iat_std": np.float64,
    "fwd_iat_tot": np.float64,
    "fwd_iat_max": np.float64,
    "fwd_iat_min": np.float64,
    "fwd_iat_mean": np.float64,
    "fwd_iat_std": np.float64,
    "bwd_iat_tot": np.float64,
    "bwd_iat_max": np.float64,
    "bwd_iat_min": np.float64,
    "bwd_iat_mean": np.float64,
    "bwd_iat_std": np.float64,
    "fwd_psh_flags": np.float64,
    "bwd_psh_flags": np.float64,
    "fwd_urg_flags": np.float64,
    "bwd_urg_flags": np.float64,
    "fin_flag_cnt": np.float64,
    "syn_flag_cnt": np.float64,
    "rst_flag_cnt": np.float64,
    "psh_flag_cnt": np.float64,
    "ack_flag_cnt": np.float64,
    "urg_flag_cnt": np.float64,
    "ece_flag_cnt": np.float64,
    "down_up_ratio": np.float64,
    "pkt_size_avg": np.float64,
    "init_fwd_win_byts": np.float64,
    "init_bwd_win_byts": np.float64,
    "active_max": np.float64,
    "active_min": np.float64,
    "active_mean": np.float64,
    "active_std": np.float64,
    "idle_max": np.float64,
    "idle_min": np.float64,
    "idle_mean": np.float64,
    "idle_std": np.float64,
    "fwd_byts_b_avg": np.float64,
    "fwd_pkts_b_avg": np.float64,
    "bwd_byts_b_avg": np.float64,
    "bwd_pkts_b_avg": np.float64,
    "fwd_blk_rate_avg": np.float64,
    "bwd_blk_rate_avg": np.float64,
    "Target": np.int32
}
