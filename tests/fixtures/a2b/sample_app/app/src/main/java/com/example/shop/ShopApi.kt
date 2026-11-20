package com.example.shop

import retrofit2.http.*

// Synthetic test fixture for Vulnix A2B static analysis. Hosts use the reserved .test TLD.
interface ShopApi {
    @GET("v1/users/{userId}/orders")
    suspend fun orders(@Path("userId") userId: String): List<Order>

    @GET("v1/orders/{orderId}")
    suspend fun order(@Path("orderId") orderId: String): Order

    @POST("v1/orders")
    suspend fun createOrder(@Body body: NewOrder): Order

    @GET("v1/products")
    suspend fun search(@Query("q") q: String): List<Product>

    @GET("internal/admin/stats")
    suspend fun adminStats(): Stats
}

object Net {
    const val BASE_URL = "https://api.shop-a2b.test/"
    fun auth(token: String) = "Bearer " + token   // sent as the Authorization header
}
