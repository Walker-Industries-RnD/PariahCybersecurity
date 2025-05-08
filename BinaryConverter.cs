using System.Text.Json;
using System.Text.Json.Serialization;
using Ceras;
using Newtonsoft.Json.Linq;

//From https://gist.github.com/LorenzGit/2cd665b6b588a8bb75c1a53f4d6b240a

//Turned Async and Made Secure

////USING BINARY FORMATTER	
// Convert an object to a byte array

//Updated; we now try with Ceras; if the object type isn't supported, we fall back to JSON serialization. This means we improve performance
//Whenever possible AND can handle weird custom objects

public static class BinaryConverter
{
    private static readonly JsonSerializerOptions _options = new JsonSerializerOptions
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters =
        {
            new JTokenConverter()
        }
    };

    public static async Task<byte[]> NCObjectToByteArrayAsync<T>(
        T obj,
        SerializerConfig? config = null,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var serializer = config != null ? new CerasSerializer(config) : new CerasSerializer();
            var data = serializer.Serialize(obj);
            return data;
        }
        catch (Exception cerasEx)
        {
            // Fallback to JSON
            await using var ms = new MemoryStream();
            await JsonSerializer
                  .SerializeAsync(ms, obj, _options, cancellationToken)
                  .ConfigureAwait(false);
            return ms.ToArray();
        }
    }

    public static async Task<T?> NCByteArrayToObjectAsync<T>(
        byte[] data,
        SerializerConfig? config = null,
        CancellationToken cancellationToken = default)
    {
        // First try Ceras
        try
        {
            var serializer = config != null ? new CerasSerializer(config) : new CerasSerializer();
            return serializer.Deserialize<T>(data);
        }
        catch (Exception cerasEx)
        {
            // Fallback to JSON
            await using var ms = new MemoryStream(data);
            return await JsonSerializer
                         .DeserializeAsync<T>(ms, _options, cancellationToken)
                         .ConfigureAwait(false);
        }
    }



private class JTokenConverter : JsonConverter<JToken>
    {
        public override JToken Read(
            ref Utf8JsonReader reader,
            Type typeToConvert,
            JsonSerializerOptions options)
        {
            // Parse the JSON fragment into a JsonDocument, then into a JToken.
            using var doc = JsonDocument.ParseValue(ref reader);
            return JToken.Parse(doc.RootElement.GetRawText());
        }

        public override void Write(
            Utf8JsonWriter writer,
            JToken value,
            JsonSerializerOptions options)
        {
            // Write the JToken’s raw JSON directly into the Utf8JsonWriter
            writer.WriteRawValue(value.ToString(Newtonsoft.Json.Formatting.None));
        }
    }






}
