using MongoDB.Driver;

namespace IdentityServer_BE.Data
{
    public class MongoDbContext
    {
        private readonly IMongoDatabase _database;

        public MongoDbContext(IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("MongoDB");
            var client = new MongoClient(connectionString);
            _database = client.GetDatabase("IdentityDB");
        }

        public IMongoDatabase Database => _database;

        public IMongoCollection<T> GetCollection<T>(string name)
        {
            return _database.GetCollection<T>(name);
        }
    }
}