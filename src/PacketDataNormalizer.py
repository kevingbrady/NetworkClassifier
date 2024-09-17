class PacketDataNormalizer:
    def __init__(self, normalization_method='zscore'):

        assert normalization_method == 'l2' or normalization_method == 'zscore'

        self.normalization_method = normalization_method
        self.min = {}
        self.max = {}
        self.mean = {}
        self.std = {}

    def __call__(self, packet_data, packet_count):

        packet_data = {x: self.update_packet_data(x, y, packet_count) for x, y in packet_data.items()}
        return packet_data

    def update_packet_data(self, key, value, packet_count):

        if packet_count == 1:

            self.min[key] = value
            self.max[key] = value
            self.mean[key] = value
            self.std[key] = value

        else:
            self.min[key] = min(self.min[key], value)
            self.max[key] = max(self.max[key], value)

            oldMean = self.mean[key]
            oldStd = self.std[key]

            self.mean[key] = (oldMean + (value - oldMean)) / 2
            self.std[key] = oldStd + (value - oldMean) * (value - self.mean[key])

            return self.normalize(key, value)

    def normalize(self, key, value):
        if self.normalization_method == 'l2':
            return (value - self.min[key]) / (self.max[key] - self.min[key])
        elif self.normalization_method == 'zscore':
            return (value - self.mean[key]) / self.std[key] if self.std[key] != 0 else 0.0
