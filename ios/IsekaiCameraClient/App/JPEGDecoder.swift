import ImageIO
import UIKit

/// MJPEG frame → `UIImage`, via ImageIO.
enum JPEGDecoder {
    /// Decode one frame, or nil if the data is not a readable image.
    ///
    /// Call this off the main thread: `kCGImageSourceShouldCacheImmediately`
    /// does the pixel work here rather than leaving it for the first draw.
    static func decode(_ jpeg: Data) -> UIImage? {
        guard let source = CGImageSourceCreateWithData(jpeg as CFData, nil) else { return nil }
        let options: [CFString: Any] = [
            kCGImageSourceShouldCache: true,
            kCGImageSourceShouldCacheImmediately: true,
        ]
        guard let image = CGImageSourceCreateImageAtIndex(source, 0, options as CFDictionary) else {
            return nil
        }
        return UIImage(cgImage: image)
    }
}
