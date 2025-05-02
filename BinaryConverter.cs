using System;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Ceras;
using Newtonsoft.Json.Linq;
using static Microsoft.IO.RecyclableMemoryStreamManager;

//From https://gist.github.com/LorenzGit/2cd665b6b588a8bb75c1a53f4d6b240a

//Turned Async and Made Secure

////USING BINARY FORMATTER	
// Convert an object to a byte array

public class BinaryConverter
{

        public static async Task<byte[]> ObjectToByteArrayAsync<T>(T obj, SerializerConfig configs = null)
        {
            CerasSerializer Serializer;

            if (configs != null)
            {
                Serializer = new CerasSerializer(configs);
            }

            else
            {
                Serializer = new CerasSerializer();
            }


            byte[] data = Serializer.Serialize(obj);

            using var ms = new MemoryStream();
            await ms.WriteAsync(data, 0, data.Length);
            return ms.ToArray();
        }

        public static async Task<T> ByteArrayToObjectAsync<T>(byte[] bytes, SerializerConfig configs = null)
        {
            CerasSerializer Serializer;

            if (configs != null)
            {
                Serializer = new CerasSerializer(configs);
            }

            else
            {
                Serializer = new CerasSerializer();
            }


            using var ms = new MemoryStream();
            await ms.WriteAsync(bytes, 0, bytes.Length);
            ms.Position = 0;

            byte[] buffer = ms.ToArray();
            return Serializer.Deserialize<T>(buffer);
        }



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
        CancellationToken cancellationToken = default)
    {
        await using var ms = new MemoryStream();
        await JsonSerializer
              .SerializeAsync(ms, obj, _options, cancellationToken)
              .ConfigureAwait(false);

        return ms.ToArray();
    }


    public static async Task<T?> NCByteArrayToObjectAsync<T>(
        byte[] data,
        CancellationToken cancellationToken = default)
    {
        await using var ms = new MemoryStream(data);
        return await JsonSerializer
                     .DeserializeAsync<T>(ms, _options, cancellationToken)
                     .ConfigureAwait(false);
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
