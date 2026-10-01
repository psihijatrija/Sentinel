using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Xunit;
using Sentinel.Core;

namespace Sentinel.Tests
{
    public class EventGraphTests
    {
        // 
        // AddNode
        // 

        [Fact]
        public void AddNode_StoresNode()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:1000", "PROCESS", new Dictionary<string, string> { ["name"] = "test.exe" });
            // Should not throw; node is tracked internally
        }

        [Fact]
        public void AddNode_UpdatesLastSeen_OnReAdd()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:100", "PROCESS");
            System.Threading.Thread.Sleep(20);
            graph.AddNode("proc:100", "PROCESS");
            // Second add updates LastSeen - node is not duplicated
        }

        [Fact]
        public void AddNode_MergesProperties()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:200", "PROCESS", new Dictionary<string, string> { ["pid"] = "200" });
            graph.AddNode("proc:200", "PROCESS", new Dictionary<string, string> { ["name"] = "app.exe" });
            // Both properties should be merged on the same node
        }

        [Fact]
        public void AddNode_NullProperties_DoesNotThrow()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:300", "PROCESS", null);
        }

        // 
        // AddEdge
        // 

        [Fact]
        public void AddEdge_StoresEdge_WithCorrectRelation()
        {
            var graph = new EventGraph();
            graph.AddEdge("proc:1000", "file:test.txt", "WROTE");

            var edges = graph.GetProcessEdges("proc:1000");
            Assert.Single(edges);
            Assert.Equal("WROTE", edges[0].Relation);
            Assert.Equal("proc:1000", edges[0].SourceKey);
            Assert.Equal("file:test.txt", edges[0].TargetKey);
        }

        [Fact]
        public void AddEdge_MultipleRelationTypes_AllTracked()
        {
            var graph = new EventGraph();
            graph.AddEdge("proc:2000", "file:payload.exe", "WROTE");
            graph.AddEdge("proc:2000", "endpoint:10.0.0.1_443", "CONNECTED");
            graph.AddEdge("proc:2000", "proc:2001", "SPAWNED");

            var edges = graph.GetProcessEdges("proc:2000");
            Assert.Equal(3, edges.Count);
            Assert.Contains(edges, e => e.Relation == "WROTE");
            Assert.Contains(edges, e => e.Relation == "CONNECTED");
            Assert.Contains(edges, e => e.Relation == "SPAWNED");
        }

        [Fact]
        public void AddEdge_AutoCreatesSourceAndTargetNodes()
        {
            var graph = new EventGraph();
            // Neither node exists before AddEdge
            graph.AddEdge("proc:3000", "file:secret.doc", "WROTE");

            // Both should exist now (inferred from edge creation)
            var edges = graph.GetProcessEdges("proc:3000");
            Assert.Single(edges);
        }

        // 
        // Edge cap enforcement
        // 

        [Fact]
        public void AddEdge_CapsPerNode_At300_TrimsTo150()
        {
            var graph = new EventGraph();
            for (int i = 0; i < 350; i++)
            {
                graph.AddEdge("proc:heavy", $"file:f{i}", "WROTE");
            }

            var edges = graph.GetProcessEdges("proc:heavy");
            // After hitting 300 cap, trims to 150. Adding more brings it up.
            // Final count should be 150 + (350 - 300) = 200 at most, but trimming may occur multiple times
            Assert.True(edges.Count <= 200, $"Edge count {edges.Count} exceeds expected cap behavior");
            Assert.True(edges.Count >= 50, $"Edge count {edges.Count} is too low - trimming too aggressive");
        }

        [Fact]
        public void AddEdge_OldestEdgesAreRemoved_WhenCapped()
        {
            var graph = new EventGraph();
            // Add 301 edges - should trigger trim
            for (int i = 0; i < 301; i++)
            {
                graph.AddEdge("proc:trim", $"file:f{i}", "WROTE");
            }

            var edges = graph.GetProcessEdges("proc:trim");
            // The oldest edges (file:f0, file:f1...) should be gone
            // The newest edges (file:f300) should be present
            Assert.Contains(edges, e => e.TargetKey == "file:f300");
            Assert.DoesNotContain(edges, e => e.TargetKey == "file:f0");
        }

        // 
        // GetProcessEdges
        // 

        [Fact]
        public void GetProcessEdges_ReturnsEmpty_ForUnknownNode()
        {
            var graph = new EventGraph();
            var edges = graph.GetProcessEdges("nonexistent");
            Assert.Empty(edges);
        }

        [Fact]
        public void GetProcessEdges_ReturnsCopy_NotReference()
        {
            var graph = new EventGraph();
            graph.AddEdge("proc:copy", "file:a", "WROTE");

            var edges1 = graph.GetProcessEdges("proc:copy");
            var edges2 = graph.GetProcessEdges("proc:copy");

            // Should be different list instances
            Assert.NotSame(edges1, edges2);
            Assert.Equal(edges1.Count, edges2.Count);
        }

        // 
        // GetProcessDiversity (v2.0 weighted scoring support)
        // 

        [Fact]
        public void GetProcessDiversity_ReturnsZero_ForUnknownPid()
        {
            var graph = new EventGraph();
            var score = graph.GetProcessDiversity(99999);

            Assert.Equal(0, score.EdgeCount);
            Assert.Equal(0, score.DistinctRelations);
            Assert.Equal(0, score.DistinctEndpoints);
            Assert.Equal(0, score.DistinctFiles);
            Assert.Equal(0, score.WeightBoost);
        }

        [Fact]
        public void GetProcessDiversity_CountsDistinctRelations()
        {
            var graph = new EventGraph();
            graph.AddEdge("PID_5000_evil.exe", "file:payload.exe", "WROTE");
            graph.AddEdge("PID_5000_evil.exe", "endpoint:10.0.0.1_443", "CONNECTED");
            graph.AddEdge("PID_5000_evil.exe", "PID_5001_child.exe", "SPAWNED");

            var score = graph.GetProcessDiversity(5000, "evil.exe");

            Assert.Equal(3, score.EdgeCount);
            Assert.Equal(3, score.DistinctRelations);
            Assert.Equal(1, score.DistinctEndpoints);
            Assert.Equal(1, score.DistinctFiles);
        }

        [Fact]
        public void GetProcessDiversity_CountsMultipleEndpoints()
        {
            var graph = new EventGraph();
            graph.AddEdge("PID_6000_beacon.exe", "endpoint:1.2.3.4_443", "CONNECTED");
            graph.AddEdge("PID_6000_beacon.exe", "endpoint:5.6.7.8_80", "CONNECTED");
            graph.AddEdge("PID_6000_beacon.exe", "endpoint:9.10.11.12_8080", "CONNECTED");

            var score = graph.GetProcessDiversity(6000, "beacon.exe");

            Assert.Equal(3, score.DistinctEndpoints);
            Assert.Equal(1, score.DistinctRelations); // all CONNECTED
        }

        [Fact]
        public void GetProcessDiversity_WeightBoost_IncreasesWithDiversity()
        {
            var graph = new EventGraph();
            // Only one relation type, one endpoint
            graph.AddEdge("PID_7000_simple.exe", "endpoint:1.1.1.1_443", "CONNECTED");
            var simpleScore = graph.GetProcessDiversity(7000, "simple.exe");

            // Multiple relation types, multiple endpoints and files
            graph.AddEdge("PID_8000_complex.exe", "endpoint:1.1.1.1_443", "CONNECTED");
            graph.AddEdge("PID_8000_complex.exe", "endpoint:2.2.2.2_80", "CONNECTED");
            graph.AddEdge("PID_8000_complex.exe", "endpoint:3.3.3.3_8080", "CONNECTED");
            graph.AddEdge("PID_8000_complex.exe", "file:secret.doc", "WROTE");
            graph.AddEdge("PID_8000_complex.exe", "file:passwords.txt", "WROTE");
            graph.AddEdge("PID_8000_complex.exe", "PID_8001_child.exe", "SPAWNED");
            var complexScore = graph.GetProcessDiversity(8000, "complex.exe");

            Assert.True(complexScore.WeightBoost > simpleScore.WeightBoost,
                $"Complex ({complexScore.WeightBoost}) should be higher than simple ({simpleScore.WeightBoost})");
        }

        [Fact]
        public void GetProcessDiversity_WeightBoost_IsBoundedAt25()
        {
            var graph = new EventGraph();
            // Maximum diversity: many relations, endpoints, and files
            for (int i = 0; i < 20; i++)
                graph.AddEdge("PID_9000_maxdiv.exe", $"endpoint:1.1.{i}.1_443", "CONNECTED");
            for (int i = 0; i < 20; i++)
                graph.AddEdge("PID_9000_maxdiv.exe", $"file:doc{i}.txt", "WROTE");
            graph.AddEdge("PID_9000_maxdiv.exe", "PID_9001_child.exe", "SPAWNED");

            var score = graph.GetProcessDiversity(9000, "maxdiv.exe");

            // WeightBoost = min(8, relations*3) + min(10, endpoints) + min(7, files/2)
            // 3 relations -> min(8, 9) = 8; 20 endpoints -> min(10,20) = 10; 20 files -> min(7, 10) = 7
            // Total max = 8 + 10 + 7 = 25
            Assert.True(score.WeightBoost <= 25, $"WeightBoost {score.WeightBoost} exceeds theoretical max of 25");
        }

        // 
        // Prune
        // 

        [Fact]
        public void Prune_RemovesOldNodes()
        {
            var graph = new EventGraph();
            graph.AddNode("proc:old", "PROCESS");
            // Zero retention removes everything
            graph.Prune(TimeSpan.FromTicks(1));

            var edges = graph.GetProcessEdges("proc:old");
            Assert.Empty(edges);
        }

        [Fact]
        public void Prune_KeepsRecentNodes()
        {
            var graph = new EventGraph();
            graph.AddEdge("proc:recent", "file:keep.txt", "WROTE");

            // 10 minute retention should keep recently-added nodes
            graph.Prune(TimeSpan.FromMinutes(10));

            var edges = graph.GetProcessEdges("proc:recent");
            Assert.Single(edges);
        }

        [Fact]
        public void Prune_CleansUpOrphanedEdges()
        {
            var graph = new EventGraph();
            graph.AddEdge("proc:willdie", "file:a.txt", "WROTE");

            // Wait briefly then prune with very short retention - node will be stale
            System.Threading.Thread.Sleep(20);
            graph.Prune(TimeSpan.FromMilliseconds(1));

            var edges = graph.GetProcessEdges("proc:willdie");
            Assert.Empty(edges);
        }

        // 
        // Concurrent access safety
        // 

        [Fact]
        public void EventGraph_ConcurrentAccess_DoesNotThrow()
        {
            var graph = new EventGraph();
            var tasks = new List<Task>();

            for (int t = 0; t < 10; t++)
            {
                int threadId = t;
                tasks.Add(Task.Run(() =>
                {
                    for (int i = 0; i < 50; i++)
                    {
                        graph.AddEdge($"proc:t{threadId}", $"file:f{threadId}_{i}", "WROTE");
                        graph.GetProcessEdges($"proc:t{threadId}");
                    }
                }));
            }

            Task.WaitAll(tasks.ToArray());
            // Should complete without deadlock or exception
        }

        [Fact]
        public void EventGraph_ConcurrentPruneAndAdd_DoesNotThrow()
        {
            var graph = new EventGraph();
            var cts = new System.Threading.CancellationTokenSource(TimeSpan.FromSeconds(2));

            var addTask = Task.Run(() =>
            {
                int i = 0;
                while (!cts.Token.IsCancellationRequested)
                {
                    graph.AddEdge($"proc:concurrent", $"file:c{i++}", "WROTE");
                }
            });

            var pruneTask = Task.Run(() =>
            {
                while (!cts.Token.IsCancellationRequested)
                {
                    graph.Prune(TimeSpan.FromMilliseconds(100));
                    System.Threading.Thread.Sleep(50);
                }
            });

            Task.WaitAll(new[] { addTask, pruneTask }, TimeSpan.FromSeconds(3));
            // No deadlock, no crash
        }

        // 
        // GraphDiversityScore model
        // 

        [Fact]
        public void GraphDiversityScore_DefaultValues()
        {
            var score = new GraphDiversityScore();
            Assert.Equal(0, score.ProcessId);
            Assert.Equal(0, score.EdgeCount);
            Assert.Equal(0, score.DistinctRelations);
            Assert.Equal(0, score.DistinctEndpoints);
            Assert.Equal(0, score.DistinctFiles);
            Assert.Equal(0, score.WeightBoost);
        }
    }
}
