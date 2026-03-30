namespace JwtTokenExample.Configuration
{
    public static class DataTypeHelper
    {
        private static IConfigurationRoot? configuration;

        public static void SetConfiguration(IConfigurationRoot config)
        {
            configuration = config;
        }

        public static string GetConfigurationValue(this string key)
        {
            try
            {
                string result = string.Empty;
                result = configuration.GetValue<string>(key);
                return result;
            }
            catch (Exception)
            {
                throw;
            }
        }

        public static DateTime GetDateTimeUTCPlus7()
        {
            try
            {
                DateTime utcTime = DateTime.UtcNow;
                DateTime utcTimePlus7Hours = utcTime.AddHours(7);
                return utcTimePlus7Hours;
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}