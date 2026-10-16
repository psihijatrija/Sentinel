using System;
using System.Linq;
using System.Reflection;
using Sentinel.Core;
using Xunit;

namespace Sentinel.Tests
{
    public class RuleCategoryRegistrationTests
    {
        [Fact]
        public void EveryDeclaredCategoryAndExplicitAliasIsRegisteredWithoutConstruction()
        {
            foreach (var type in typeof(IDetectionRule).Assembly.GetTypes().Where(t => typeof(IDetectionRule).IsAssignableFrom(t)))
            {
                var attribute = type.GetCustomAttribute<RuleCategoryAttribute>();
                if (attribute == null) continue;
                Assert.Equal(attribute.Category, RuleCategoryRegistry.Resolve(type.Name));
                if (!string.IsNullOrEmpty(attribute.RuleName)) Assert.Equal(attribute.Category, RuleCategoryRegistry.Resolve(attribute.RuleName));
            }
            Assert.Equal(DetectionCategory.CampaignIoC, RuleCategoryRegistry.Resolve("Campaign IOC Detection"));
        }
    }
}
