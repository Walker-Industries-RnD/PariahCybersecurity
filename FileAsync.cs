using System.Text;

/// <summary>
///     An async alternative to System.IO.File common usages
/// </summary>
public static class FileAsync
{

    //Copypasted from https://gist.github.com/adamtal3/92ee3cc0b77ecba3dfd6

    private const int BUFFER_SIZE = 0x4096;

    /// <summary>
    ///     Opens an existing file for asynchronous reading.
    /// </summary>
    /// <param name="path">Full file path</param>
    /// <returns>A read-only FileStream on the specified path.</returns>
    public static FileStream OpenRead(string path)
    {
        // Open a file stream for reading and that supports asynchronous I/O
        return new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, BUFFER_SIZE, true);
    }

    /// <summary>Opens an existing file for asynchronous writing.</summary>
    /// <param name="path">Full file path</param>
    /// <returns>An unshared FileStream on the specified path with access for writing.</returns>
    public static FileStream OpenWrite(string path)
    {
        // Open a file stream for writing and that supports asynchronous I/O
        return new FileStream(path, FileMode.OpenOrCreate, FileAccess.Write, FileShare.None, BUFFER_SIZE, true);
    }

    /// <summary>
    ///     Read entire file content as a byte array
    /// </summary>
    /// <param name="path">Full file path</param>
    public static async Task<byte[]> ReadAllBytes(string path)
    {
        using (var fs = OpenRead(path))
        {
            var buff = new byte[fs.Length];
            await fs.ReadAsync(buff, 0, (int)fs.Length);
            return buff;
        }
    }

    /// <summary>
    ///     Opens a binary file for asynchronous operation, writes the contents of the byte array into the file, and then
    ///     closes the file.
    /// </summary>
    /// <param name="path">Full file path</param>
    /// <param name="bytes">Bytes to write to the file</param>
    public static async Task WriteAllBytes(string path, byte[] bytes)
    {
        if (path == null) throw new ArgumentException("path");
        if (bytes == null) throw new ArgumentException("bytes");

        using (var fs = OpenWrite(path))
        {
            await fs.WriteAsync(bytes, 0, bytes.Length);
        }
    }

    /// <summary>
    ///     Opens a text file for async operation, reads the contents of the file into a string, and then closes the file.
    /// </summary>
    /// <param name="path">Full file path</param>
    /// <param name="encoding">File encoding. Default is UTF8</param>
    public static async Task<string> ReadAllText(string path, Encoding encoding = null)
    {
        encoding = encoding ?? Encoding.UTF8;
        using (var reader = new StreamReader(path, encoding))
        {
            return await reader.ReadToEndAsync();
        }
    }

    /// <summary>
    ///     Opens a text file for async operation, writes a string into the file, and then closes the file.
    /// </summary>
    /// <param name="path">Full file path</param>
    /// <param name="contents">File content</param>
    /// <param name="encoding">File encoding. Default is UTF8</param>
    public static async Task WriteAllText(string path, string contents, Encoding encoding = null)
    {
        encoding = encoding ?? Encoding.UTF8;
        await WriteAllBytes(path, encoding.GetBytes(contents));
    }

    /// <summary>
    ///     Opens a text file for async operation, reads the contents of the file line by line, and then closes the file.
    /// </summary>
    /// <param name="path">Full file path</param>
    /// <param name="encoding">File encoding. Default is UTF8</param>
    public static async Task<string[]> ReadAllLines(string path, Encoding encoding = null)
    {
        encoding = encoding ?? Encoding.UTF8;
        var lines = new List<string>();
        using (var reader = new StreamReader(path, encoding))
        {
            string line;
            while ((line = await reader.ReadLineAsync()) != null)
                lines.Add(line);
        }
        return lines.ToArray();
    }

    /// <summary>
    ///     Copies an existing file to a new file.
    ///     Overwriting a file of the same name is not allowed.
    /// </summary>
    public static async Task Copy(string sourceFileName, string destFileName)
    {
        using (var sourceStream = File.Open(sourceFileName, FileMode.Open))
        {
            using (var destinationStream = File.Create(destFileName))
            {
                await sourceStream.CopyToAsync(destinationStream);
            }
        }
    }

    /// <summary>
    ///     Copy an existing file to a new file.
    ///     After the copy the source file is deleted.
    ///     Overwriting a file of the same name is not allowed.
    /// </summary>
    public static async Task Move(string sourceFileName, string destFileName)
    {
        using (var sourceStream = File.Open(sourceFileName, FileMode.Open))
        {
            using (var destinationStream = File.Create(destFileName))
            {
                await sourceStream.CopyToAsync(destinationStream);
            }
        }

        File.Delete(sourceFileName);
    }
}